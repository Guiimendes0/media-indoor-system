const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const WebSocket = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;

// WebSocket para sincronização e visualização
const wss = new WebSocket.Server({ noServer: true });
const connectedClients = new Map();
const activeSyncs = new Map();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Arquivos de persistência
const DATA_FILES = {
    users: 'users.json',
    devices: 'devices.json',
    media: 'media.json',
    playlists: 'playlists.json',
    announcements: 'announcements.json'
};

// Funções para persistência
function loadData(fileName) {
    try {
        if (fs.existsSync(fileName)) {
            const data = fs.readFileSync(fileName, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error(`Erro ao carregar ${fileName}:`, error);
    }
    return [];
}

function saveData(fileName, data) {
    try {
        fs.writeFileSync(fileName, JSON.stringify(data, null, 2));
        console.log(`💾 ${fileName} salvo com sucesso`);
    } catch (error) {
        console.error(`❌ Erro ao salvar ${fileName}:`, error);
    }
}

// Carregar dados ao iniciar
const users = loadData(DATA_FILES.users);
const devices = loadData(DATA_FILES.devices);
const media = loadData(DATA_FILES.media);
const playlists = loadData(DATA_FILES.playlists);
const announcements = loadData(DATA_FILES.announcements);

console.log('📂 Dados carregados:', {
    users: users.length,
    devices: devices.length,
    media: media.length,
    playlists: playlists.length,
    announcements: announcements.length
});

// Configuração do multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads/media';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|bmp|mp4|avi|mov|mkv|webm/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Tipo de arquivo não suportado'));
        }
    },
    limits: { fileSize: 100 * 1024 * 1024 }
});

// Middleware de autenticação
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acesso necessário' });
    }

    try {
        const user = users.find(u => u.token === token);
        if (!user) {
            return res.status(403).json({ error: 'Token inválido ou sessão expirada' });
        }
        req.user = user;
        next();
    } catch (error) {
        res.status(403).json({ error: 'Token inválido' });
    }
}

// ==================== NOVAS ROTAS PARA SISTEMA MAC ====================

// Rota para registrar código de autenticação do dispositivo
app.post('/api/devices/register-code', (req, res) => {
    const { mac, authCode, expiry } = req.body;
    
    console.log(`🔐 Registrando código para MAC: ${mac}, Código: ${authCode}`);
    
    if (!mac || !authCode) {
        return res.status(400).json({ error: 'MAC e código são obrigatórios' });
    }
    
    // Verificar se o dispositivo já existe
    let device = devices.find(d => d.mac === mac);
    
    if (device) {
        // Atualizar código existente
        device.authCode = authCode;
        device.codeExpiry = expiry;
        device.lastCodeUpdate = new Date();
    } else {
        // Criar novo dispositivo pendente
        device = {
            id: Date.now().toString(),
            mac: mac,
            authCode: authCode,
            codeExpiry: expiry,
            lastCodeUpdate: new Date(),
            status: 'pending',
            name: `Dispositivo ${mac}`,
            location: 'Não definido',
            playlistId: null,
            userId: null, // Será definido na ativação
            lastSeen: null,
            createdAt: new Date()
        };
        devices.push(device);
    }
    
    saveData(DATA_FILES.devices, devices);
    
    console.log(`✅ Código registrado para MAC ${mac}`);
    
    res.json({ 
        message: 'Código registrado com sucesso',
        device: {
            mac: device.mac,
            authCode: device.authCode,
            expiry: device.codeExpiry
        }
    });
});

// ATUALIZAR: Middleware para aceitar MAC de múltiplas formas
function checkDeviceAuthorization(req, res, next) {
    // IGNORAR requisições para arquivos de mídia
    if (req.path.startsWith('/media/')) {
        return next();
    }
    
    // CORREÇÃO: Obter MAC do header, query parameter OU body
    let deviceMac = req.headers['x-device-mac'] || req.query.mac;
    
    // Para POST requests, tentar obter do body também
    if (req.method === 'POST' && !deviceMac) {
        try {
            // Não podemos ler o body duas vezes, então usamos uma flag
            if (req.body && req.body.mac) {
                deviceMac = req.body.mac;
            }
        } catch (error) {
            console.log('Não foi possível ler MAC do body');
        }
    }
    
    console.log(`🔍 Verificando autorização para MAC: ${deviceMac} - Rota: ${req.path}`);
    
    // Aplicar verificação APENAS para rotas de API do cliente
    if (req.path.startsWith('/api/client/')) {
        console.log('🔐 Rota cliente detectada, verificando dispositivos por MAC...');
        
        if (!deviceMac) {
            console.log('❌ MAC não fornecido na requisição');
            return res.status(403).json({ 
                error: 'MAC do dispositivo não fornecido',
                message: 'O dispositivo deve fornecer seu MAC address'
            });
        }
        
        // Buscar dispositivo por MAC
        const authorizedDevice = devices.find(device => 
            device.mac === deviceMac && device.status === 'active'
        );
        
        if (!authorizedDevice) {
            console.log('❌ Acesso negado para MAC:', deviceMac);
            console.log('📊 Dispositivos cadastrados ativos:');
            devices.filter(d => d.status === 'active').forEach(device => {
                console.log(`   - ${device.name}: ${device.mac} (${device.status})`);
            });
            
            return res.status(403).json({ 
                error: 'Dispositivo não autorizado',
                message: `MAC ${deviceMac} não está cadastrado como dispositivo ativo`,
                detectedMac: deviceMac
            });
        }
        
        authorizedDevice.lastSeen = new Date();
        saveData(DATA_FILES.devices, devices);
        
        console.log('✅ Acesso autorizado para:', authorizedDevice.name, `MAC: ${deviceMac}`);
        req.authorizedDevice = authorizedDevice;
    }
    
    next();
}

app.use(checkDeviceAuthorization);

// ADICIONAR este middleware para debug de todas as requisições
app.use((req, res, next) => {
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
    console.log(`🌐 ${req.method} ${req.path} - IP: ${clientIp}`);
    next();
});

// ==================== ROTAS DE AUTENTICAÇÃO ====================

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).json({ error: 'Usuário não encontrado' });
    }
    
    try {
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Senha incorreta' });
        }
        
        const token = Math.random().toString(36).substring(2) + Date.now().toString(36);
        user.token = token;
        user.lastLogin = new Date();
        saveData(DATA_FILES.users, users);
        
        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                name: user.name,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
    req.user.token = null;
    saveData(DATA_FILES.users, users);
    res.json({ message: 'Logout realizado com sucesso' });
});

// ==================== ROTAS DE USUÁRIOS ====================

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    
    const usersWithoutPassword = users.map(u => ({
        id: u.id,
        username: u.username,
        name: u.name,
        role: u.role,
        createdAt: u.createdAt,
        lastLogin: u.lastLogin
    }));
    
    res.json(usersWithoutPassword);
});

app.post('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    
    const { username, password, name, role = 'user' } = req.body;
    
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Usuário já existe' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = {
            id: Date.now().toString(),
            username,
            password: hashedPassword,
            name,
            role,
            createdAt: new Date(),
            lastLogin: null,
            token: null
        };
        
        users.push(user);
        saveData(DATA_FILES.users, users);
        
        res.json({
            id: user.id,
            username: user.username,
            name: user.name,
            role: user.role,
            createdAt: user.createdAt
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao criar usuário' });
    }
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    
    const userId = req.params.id;
    const userIndex = users.findIndex(u => u.id === userId);
    
    if (userIndex === -1) {
        return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    
    // Não permitir excluir o próprio usuário
    if (users[userIndex].id === req.user.id) {
        return res.status(400).json({ error: 'Não é possível excluir seu próprio usuário' });
    }
    
    users.splice(userIndex, 1);
    saveData(DATA_FILES.users, users);
    
    res.json({ message: 'Usuário removido com sucesso' });
});

// ==================== ROTAS DE DISPOSITIVOS ====================

app.get('/api/devices', authenticateToken, (req, res) => {
    const userDevices = req.user.role === 'admin' 
        ? devices 
        : devices.filter(device => device.userId === req.user.id);
    
    // Ordenar: dispositivos ativos primeiro, depois pendentes
    userDevices.sort((a, b) => {
        if (a.status === 'active' && b.status !== 'active') return -1;
        if (a.status !== 'active' && b.status === 'active') return 1;
        return new Date(b.lastSeen || b.createdAt) - new Date(a.lastSeen || a.createdAt);
    });
    
    res.json(userDevices);
});

// ATUALIZADA: Adicionar dispositivo por código (não por IP)
app.post('/api/devices', authenticateToken, (req, res) => {
    const { authCode, name, location, playlistId } = req.body;
    
    if (!authCode) {
        return res.status(400).json({ error: 'Código de autenticação é obrigatório' });
    }
    
    // Buscar dispositivo pendente pelo código
    const pendingDevice = devices.find(d => 
        d.authCode === authCode && 
        d.status === 'pending' &&
        (!d.codeExpiry || new Date(d.codeExpiry) > new Date())
    );
    
    if (!pendingDevice) {
        return res.status(400).json({ error: 'Código inválido ou expirado' });
    }
    
    // Ativar dispositivo
    pendingDevice.status = 'active';
    pendingDevice.userId = req.user.id;
    pendingDevice.name = name || `Dispositivo ${pendingDevice.mac}`;
    pendingDevice.location = location || 'Não definido';
    pendingDevice.playlistId = playlistId || null;
    pendingDevice.lastSeen = new Date();
    pendingDevice.activatedAt = new Date();
    pendingDevice.activatedBy = req.user.id;
    
    saveData(DATA_FILES.devices, devices);
    
    console.log(`✅ Dispositivo ativado: ${pendingDevice.name} (MAC: ${pendingDevice.mac})`);
    
    res.json({
        message: 'Dispositivo adicionado com sucesso',
        device: pendingDevice
    });
});

app.put('/api/devices/:id', authenticateToken, (req, res) => {
    const deviceId = req.params.id;
    const { name, location, playlistId } = req.body;
    
    const deviceIndex = devices.findIndex(device => 
        device.id === deviceId && (device.userId === req.user.id || req.user.role === 'admin')
    );
    
    if (deviceIndex === -1) {
        return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }
    
    devices[deviceIndex] = {
        ...devices[deviceIndex],
        name: name || devices[deviceIndex].name,
        location: location || devices[deviceIndex].location,
        playlistId: playlistId !== undefined ? playlistId : devices[deviceIndex].playlistId
    };
    
    saveData(DATA_FILES.devices, devices);
    res.json(devices[deviceIndex]);
});

app.delete('/api/devices/:id', authenticateToken, (req, res) => {
    const deviceId = req.params.id;
    const deviceIndex = devices.findIndex(device => 
        device.id === deviceId && (device.userId === req.user.id || req.user.role === 'admin')
    );
    
    if (deviceIndex === -1) {
        return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }
    
    devices.splice(deviceIndex, 1);
    saveData(DATA_FILES.devices, devices);
    res.json({ message: 'Dispositivo removido com sucesso' });
});

// NOVA: Rota para desconectar dispositivo
app.post('/api/devices/:id/disconnect', authenticateToken, (req, res) => {
    const deviceId = req.params.id;
    
    const deviceIndex = devices.findIndex(device => 
        device.id === deviceId && (device.userId === req.user.id || req.user.role === 'admin')
    );
    
    if (deviceIndex === -1) {
        return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }
    
    const device = devices[deviceIndex];
    
    // Gerar novo código para reconexão
    const newAuthCode = Math.floor(100000 + Math.random() * 900000).toString();
    const codeExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutos
    
    device.status = 'pending';
    device.authCode = newAuthCode;
    device.codeExpiry = codeExpiry.toISOString();
    device.lastSeen = null;
    device.disconnectedAt = new Date();
    device.disconnectedBy = req.user.id;
    
    saveData(DATA_FILES.devices, devices);
    
    console.log(`🔌 Dispositivo desconectado: ${device.name} (MAC: ${device.mac})`);
    
    // Notificar dispositivo via WebSocket (se conectado)
    const client = connectedClients.get(deviceId);
    if (client && client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(JSON.stringify({
            type: 'device_disconnected',
            message: 'Dispositivo desconectado pelo administrador',
            timestamp: new Date()
        }));
        client.ws.close();
    }
    
    res.json({ 
        message: 'Dispositivo desconectado com sucesso',
        device: {
            id: device.id,
            name: device.name,
            mac: device.mac,
            status: device.status
        }
    });
});

// ==================== ROTAS DE SINCRONIZAÇÃO POR PLAYLIST ====================

// CORRIGIDA: Sincronização que respeita o estado atual da playlist
app.post('/api/playlists/:id/sync', authenticateToken, (req, res) => {
    const playlistId = req.params.id;
    
    console.log(`🔄 Recebida solicitação de sincronização para playlist: ${playlistId}`);
    
    const playlistIndex = playlists.findIndex(p => 
        p.id === playlistId && (p.userId === req.user.id || req.user.role === 'admin')
    );
    
    if (playlistIndex === -1) {
        console.log(`❌ Playlist não encontrada: ${playlistId}`);
        return res.status(404).json({ error: 'Playlist não encontrada' });
    }
    
    const playlist = playlists[playlistIndex];
    
    // VERIFICAR: Se a playlist não tem syncInfo, criar um novo
    if (!playlist.syncInfo) {
        console.log('📝 Criando syncInfo inicial para playlist');
        playlist.syncInfo = {
            currentMediaIndex: 0,
            mediaStartTime: new Date().toISOString(),
            lastSync: new Date().toISOString(),
            syncBy: req.user.id
        };
        saveData(DATA_FILES.playlists, playlists);
    }
    
    const syncInfo = playlist.syncInfo;
    
    console.log(`📊 Sincronizando playlist: ${playlist.name}`);
    console.log(`📈 Estado atual da playlist: Mídia ${syncInfo.currentMediaIndex}, Iniciada em: ${syncInfo.mediaStartTime}`);
    
    // Encontrar todos os dispositivos ativos que usam esta playlist
    const devicesUsingPlaylist = devices.filter(device => 
        device.playlistId === playlistId && device.status === 'active'
    );
    
    const deviceIds = devicesUsingPlaylist.map(device => device.id);
    
    console.log(`📺 Dispositivos ativos encontrados: ${deviceIds.length}`);
    
    if (deviceIds.length === 0) {
        console.log(`❌ Nenhum dispositivo ativo usando a playlist: ${playlistId}`);
        return res.status(400).json({ error: 'Nenhum dispositivo ativo usando esta playlist' });
    }
    
    // CALCULAR tempo decorrido desde o início da mídia atual
    const mediaStartTime = new Date(syncInfo.mediaStartTime);
    const now = new Date();
    const elapsedTime = now - mediaStartTime;
    
    console.log(`⏰ Tempo decorrido desde início da mídia: ${elapsedTime}ms`);
    
    // CORREÇÃO: Usar a função diretamente, não com 'this'
    const currentState = calculateCurrentPlaylistState(playlistIndex, elapsedTime);
    
    console.log(`🎯 Estado calculado:`, {
        currentMediaIndex: currentState.currentMediaIndex,
        elapsedTime: currentState.elapsedTime,
        remainingTime: currentState.remainingTime,
        mediaDuration: currentState.mediaDuration
    });
    
    // ATUALIZAR syncInfo com o estado calculado
    playlists[playlistIndex].syncInfo = {
        currentMediaIndex: currentState.currentMediaIndex,
        mediaStartTime: syncInfo.mediaStartTime, // Mantém o tempo original
        lastSync: now.toISOString(),
        syncBy: req.user.id,
        calculatedElapsedTime: currentState.elapsedTime,
        calculatedRemainingTime: currentState.remainingTime
    };
    
    saveData(DATA_FILES.playlists, playlists);
    
    // PREPARAR mensagem de sincronização
    const syncMessage = {
        type: 'sync_command',
        command: 'sync_playlist',
        playlistId: playlistId,
        currentMediaIndex: currentState.currentMediaIndex,
        mediaStartTime: syncInfo.mediaStartTime,
        elapsedTime: currentState.elapsedTime,
        remainingTime: currentState.remainingTime,
        mediaDuration: currentState.mediaDuration,
        timestamp: now.toISOString(),
        serverTime: Date.now()
    };
    
    // ENVIAR para dispositivos
    const connectedCount = broadcastToDevices(deviceIds, syncMessage);
    
    console.log(`✅ Playlist ${playlistId} sincronizada!`);
    console.log(`📤 Enviado para ${connectedCount} dispositivos: Mídia ${currentState.currentMediaIndex}, ${Math.round(currentState.remainingTime/1000)}s restantes`);
    
    res.json({ 
        message: `Playlist sincronizada para ${deviceIds.length} dispositivo(s)`,
        playlistId: playlistId,
        deviceIds: deviceIds,
        syncInfo: currentState,
        connectedCount: connectedCount
    });
});

// CORREÇÃO COMPLETA: Função para calcular o estado atual da playlist
function calculateCurrentPlaylistState(playlistIndex, totalElapsedTime) {
    const playlist = playlists[playlistIndex];
    
    if (!playlist.mediaIds || playlist.mediaIds.length === 0) {
        return {
            currentMediaIndex: 0,
            elapsedTime: 0,
            remainingTime: 0,
            mediaDuration: 0
        };
    }
    
    console.log(`🔍 Calculando estado para playlist com ${playlist.mediaIds.length} mídias, tempo decorrido: ${totalElapsedTime}ms`);
    
    // CALCULAR duração total da playlist
    const totalPlaylistDuration = calculateTotalPlaylistDuration(playlistIndex);
    console.log(`📊 Duração total da playlist: ${totalPlaylistDuration}ms`);
    
    // SE o tempo decorrido é maior que a duração total, usar módulo para reiniciar
    const effectiveElapsedTime = totalElapsedTime % totalPlaylistDuration;
    console.log(`⏰ Tempo efetivo decorrido: ${effectiveElapsedTime}ms`);
    
    let accumulatedTime = 0;
    let currentMediaIndex = 0;
    let currentElapsedTime = effectiveElapsedTime;
    
    // PERCORRER mídias para encontrar a atual
    for (let i = 0; i < playlist.mediaIds.length; i++) {
        const mediaId = playlist.mediaIds[i];
        const mediaItem = media.find(m => m.id === mediaId);
        
        if (mediaItem) {
            const mediaDuration = (mediaItem.displayTime || 10) * 1000;
            
            console.log(`🎬 Mídia ${i}: ${mediaItem.originalName}, Duração: ${mediaDuration}ms, Acumulado: ${accumulatedTime}ms`);
            
            // VERIFICAR se o tempo efetivo cai dentro desta mídia
            if (effectiveElapsedTime < accumulatedTime + mediaDuration) {
                currentMediaIndex = i;
                currentElapsedTime = effectiveElapsedTime - accumulatedTime;
                console.log(`✅ Mídia atual encontrada: índice ${i}, tempo na mídia: ${currentElapsedTime}ms`);
                break;
            }
            
            accumulatedTime += mediaDuration;
        }
    }
    
    // OBTER a mídia atual
    const currentMediaId = playlist.mediaIds[currentMediaIndex];
    const currentMedia = media.find(m => m.id === currentMediaId);
    const mediaDuration = (currentMedia?.displayTime || 10) * 1000;
    const remainingTime = Math.max(0, mediaDuration - currentElapsedTime);
    
    console.log(`🎯 Resultado final: Mídia ${currentMediaIndex} (${currentMedia?.originalName}), ${Math.round(currentElapsedTime/1000)}s decorridos, ${Math.round(remainingTime/1000)}s restantes`);
    
    return {
        currentMediaIndex: currentMediaIndex,
        elapsedTime: currentElapsedTime,
        remainingTime: remainingTime,
        mediaDuration: mediaDuration
    };
}

// CORREÇÃO: Função para calcular duração total da playlist
function calculateTotalPlaylistDuration(playlistIndex) {
    const playlist = playlists[playlistIndex];
    let totalDuration = 0;
    
    playlist.mediaIds.forEach(mediaId => {
        const mediaItem = media.find(m => m.id === mediaId);
        if (mediaItem) {
            totalDuration += (mediaItem.displayTime || 10) * 1000;
        }
    });
    
    return totalDuration;
}

// CORREÇÃO: Rota para obter informações da playlist (acessível para dispositivos)
app.get('/api/playlists/:id/sync-info', (req, res) => {
    const playlistId = req.params.id;
    
    console.log(`🔍 Buscando informações de sincronização da playlist: ${playlistId}`);
    
    const playlist = playlists.find(p => p.id === playlistId);
    if (!playlist) {
        return res.status(404).json({ error: 'Playlist não encontrada' });
    }
    
    // SE não tem syncInfo, criar um
    if (!playlist.syncInfo) {
        console.log('📝 Criando syncInfo inicial para playlist');
        playlist.syncInfo = {
            currentMediaIndex: 0,
            mediaStartTime: new Date().toISOString(),
            lastSync: new Date().toISOString()
        };
        saveData(DATA_FILES.playlists, playlists);
    }
    
    // CALCULAR estado atual
    const mediaStartTime = new Date(playlist.syncInfo.mediaStartTime);
    const now = new Date();
    const elapsedTime = now - mediaStartTime;
    const currentState = calculateCurrentPlaylistState(playlists.indexOf(playlist), elapsedTime);
    
    console.log(`📊 Estado atual da playlist ${playlistId}:`, {
        mediaIndex: currentState.currentMediaIndex,
        elapsedTime: Math.round(currentState.elapsedTime / 1000) + 's',
        remainingTime: Math.round(currentState.remainingTime / 1000) + 's'
    });
    
    res.json({
        playlistId: playlistId,
        syncInfo: playlist.syncInfo,
        currentState: currentState,
        calculatedAt: new Date().toISOString()
    });
});

// ATUALIZADA: Quando uma playlist é criada/alterada, inicializar syncInfo
function initializePlaylistSyncInfo(playlistIndex) {
    const playlist = playlists[playlistIndex];
    
    if (!playlist.syncInfo) {
        playlist.syncInfo = {
            currentMediaIndex: 0,
            mediaStartTime: new Date().toISOString(),
            lastSync: new Date().toISOString(),
            elapsedTime: 0,
            remainingTime: (media.find(m => m.id === playlist.mediaIds[0])?.displayTime || 10) * 1000
        };
    }
}


// ==================== ROTAS DE MÍDIAS ====================

app.get('/api/media', authenticateToken, (req, res) => {
    const userMedia = req.user.role === 'admin' 
        ? media 
        : media.filter(m => m.userId === req.user.id);
    
    // Ordenar por ordem definida
    userMedia.sort((a, b) => (a.order || 0) - (b.order || 0));
    res.json(userMedia);
});

app.post('/api/media', authenticateToken, upload.single('media'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Nenhum arquivo enviado' });
    }

    const { displayTime = 10 } = req.body;
    
    // Determinar ordem
    const userMedia = media.filter(m => m.userId === req.user.id);
    const maxOrder = userMedia.length > 0 ? Math.max(...userMedia.map(m => m.order || 0)) : 0;
    
    const mediaItem = {
        id: Date.now().toString(),
        filename: req.file.filename,
        originalName: req.file.originalname,
        path: `/media/${req.file.filename}`,
        type: req.file.mimetype.split('/')[0],
        mediaType: 'upload',
        displayTime: parseInt(displayTime),
        size: req.file.size,
        userId: req.user.id,
        order: maxOrder + 1,
        uploadedAt: new Date(),
        isExternal: false
    };

    media.push(mediaItem);
    saveData(DATA_FILES.media, media);
    res.json(mediaItem);
});

app.post('/api/media/external', authenticateToken, (req, res) => {
    const { name, url, type, displayTime = 10 } = req.body;
    
    if (!name || !url || !type) {
        return res.status(400).json({ error: 'Nome, URL e tipo são obrigatórios' });
    }
    
    // Determinar ordem
    const userMedia = media.filter(m => m.userId === req.user.id);
    const maxOrder = userMedia.length > 0 ? Math.max(...userMedia.map(m => m.order || 0)) : 0;
    
    const mediaItem = {
        id: Date.now().toString(),
        filename: url,
        originalName: name,
        path: url,
        type: type === 'website' ? 'website' : 'video',
        mediaType: type,
        displayTime: parseInt(displayTime),
        size: 0,
        userId: req.user.id,
        order: maxOrder + 1,
        uploadedAt: new Date(),
        isExternal: true
    };

    media.push(mediaItem);
    saveData(DATA_FILES.media, media);
    res.json(mediaItem);
});

app.put('/api/media/:id', authenticateToken, (req, res) => {
    const mediaId = req.params.id;
    const { originalName, displayTime, path, order } = req.body;
    
    const mediaIndex = media.findIndex(m => 
        m.id === mediaId && (m.userId === req.user.id || req.user.role === 'admin')
    );
    
    if (mediaIndex === -1) {
        return res.status(404).json({ error: 'Mídia não encontrada' });
    }
    
    media[mediaIndex] = {
        ...media[mediaIndex],
        originalName: originalName || media[mediaIndex].originalName,
        displayTime: displayTime !== undefined ? parseInt(displayTime) : media[mediaIndex].displayTime,
        path: path || media[mediaIndex].path,
        order: order !== undefined ? parseInt(order) : media[mediaIndex].order
    };
    
    saveData(DATA_FILES.media, media);
    res.json(media[mediaIndex]);
});

// Reordenar mídias
app.post('/api/media/reorder', authenticateToken, (req, res) => {
    const { mediaOrder } = req.body; // Array de {id, order}
    
    mediaOrder.forEach(({ id, order }) => {
        const mediaIndex = media.findIndex(m => 
            m.id === id && (m.userId === req.user.id || req.user.role === 'admin')
        );
        
        if (mediaIndex !== -1) {
            media[mediaIndex].order = order;
        }
    });
    
    saveData(DATA_FILES.media, media);
    res.json({ message: 'Ordem das mídias atualizada' });
});

app.delete('/api/media/:id', authenticateToken, (req, res) => {
    const mediaId = req.params.id;
    const mediaIndex = media.findIndex(m => 
        m.id === mediaId && (m.userId === req.user.id || req.user.role === 'admin')
    );
    
    if (mediaIndex === -1) {
        return res.status(404).json({ error: 'Mídia não encontrada' });
    }
    
    const mediaItem = media[mediaIndex];
    if (!mediaItem.isExternal) {
        try {
            const filePath = path.join('uploads/media', mediaItem.filename);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
                console.log('🗑️ Arquivo removido:', mediaItem.filename);
            }
        } catch (error) {
            console.error('Erro ao remover arquivo:', error);
        }
    }
    
    media.splice(mediaIndex, 1);
    saveData(DATA_FILES.media, media);
    res.json({ message: 'Mídia removida com sucesso' });
});

// ==================== ROTAS DE PLAYLISTS ====================

app.get('/api/playlists', authenticateToken, (req, res) => {
    const userPlaylists = req.user.role === 'admin' 
        ? playlists 
        : playlists.filter(p => p.userId === req.user.id);
    res.json(userPlaylists);
});

// ATUALIZAR as rotas de playlist para inicializar syncInfo
app.post('/api/playlists', authenticateToken, (req, res) => {
    const { name, mediaIds, schedule, mediaOrder = [] } = req.body;
    
    // Verificar se as mídias pertencem ao usuário
    const userMediaIds = media.filter(m => m.userId === req.user.id).map(m => m.id);
    const validMediaIds = mediaIds.filter(id => userMediaIds.includes(id));
    
    const playlist = {
        id: Date.now().toString(),
        name,
        mediaIds: validMediaIds,
        mediaOrder: mediaOrder,
        schedule: schedule || {},
        userId: req.user.id,
        createdAt: new Date(),
        syncInfo: {
            currentMediaIndex: 0,
            mediaStartTime: new Date().toISOString(),
            lastSync: new Date().toISOString(),
            elapsedTime: 0,
            remainingTime: validMediaIds.length > 0 ? 
                (media.find(m => m.id === validMediaIds[0])?.displayTime || 10) * 1000 : 0
        }
    };
    
    playlists.push(playlist);
    saveData(DATA_FILES.playlists, playlists);
    res.json(playlist);
});

app.put('/api/playlists/:id', authenticateToken, (req, res) => {
    const playlistId = req.params.id;
    const { name, mediaIds, schedule, mediaOrder } = req.body;
    
    const playlistIndex = playlists.findIndex(p => 
        p.id === playlistId && (p.userId === req.user.id || req.user.role === 'admin')
    );
    
    if (playlistIndex === -1) {
        return res.status(404).json({ error: 'Playlist não encontrada' });
    }
    
    // Verificar se as mídias pertencem ao usuário
    const userMediaIds = media.filter(m => m.userId === req.user.id).map(m => m.id);
    const validMediaIds = mediaIds ? mediaIds.filter(id => userMediaIds.includes(id)) : playlists[playlistIndex].mediaIds;
    
    // Manter o syncInfo existente ou criar novo
    const existingSyncInfo = playlists[playlistIndex].syncInfo;
    const newSyncInfo = existingSyncInfo || {
        currentMediaIndex: 0,
        mediaStartTime: new Date().toISOString(),
        lastSync: new Date().toISOString(),
        elapsedTime: 0,
        remainingTime: validMediaIds.length > 0 ? 
            (media.find(m => m.id === validMediaIds[0])?.displayTime || 10) * 1000 : 0
    };
    
    playlists[playlistIndex] = {
        ...playlists[playlistIndex],
        name: name || playlists[playlistIndex].name,
        mediaIds: validMediaIds,
        mediaOrder: mediaOrder || playlists[playlistIndex].mediaOrder,
        schedule: schedule || playlists[playlistIndex].schedule,
        syncInfo: newSyncInfo
    };
    
    saveData(DATA_FILES.playlists, playlists);
    res.json(playlists[playlistIndex]);
});

app.delete('/api/playlists/:id', authenticateToken, (req, res) => {
    const playlistId = req.params.id;
    const playlistIndex = playlists.findIndex(p => 
        p.id === playlistId && (p.userId === req.user.id || req.user.role === 'admin')
    );
    
    if (playlistIndex === -1) {
        return res.status(404).json({ error: 'Playlist não encontrada' });
    }
    
    playlists.splice(playlistIndex, 1);
    saveData(DATA_FILES.playlists, playlists);
    res.json({ message: 'Playlist removida com sucesso' });
});

// ==================== ROTAS DE PRONUNCIAMENTOS ====================

app.get('/api/announcements', authenticateToken, (req, res) => {
    const userAnnouncements = announcements.filter(a => a.userId === req.user.id);
    res.json(userAnnouncements);
});

app.post('/api/announcements', authenticateToken, (req, res) => {
    const { name, mediaId, deviceIds, displayTime } = req.body;
    
    // Verificar se a mídia pertence ao usuário
    const userMedia = media.filter(m => m.userId === req.user.id);
    if (!userMedia.find(m => m.id === mediaId)) {
        return res.status(400).json({ error: 'Mídia não encontrada ou não pertence ao usuário' });
    }
    
    // Verificar se os dispositivos pertencem ao usuário
    const userDevices = devices.filter(d => d.userId === req.user.id);
    const validDeviceIds = deviceIds.filter(deviceId => 
        userDevices.find(d => d.id === deviceId && d.status === 'active')
    );
    
    if (validDeviceIds.length === 0) {
        return res.status(400).json({ error: 'Nenhum dispositivo válido encontrado' });
    }
    
    const announcement = {
        id: Date.now().toString(),
        name,
        mediaId,
        deviceIds: validDeviceIds,
        displayTime: parseInt(displayTime) || 30,
        userId: req.user.id,
        status: 'active',
        createdAt: new Date(),
        scheduledFor: new Date()
    };
    
    announcements.push(announcement);
    saveData(DATA_FILES.announcements, announcements);
    
    // Enviar para dispositivos
    const mediaItem = media.find(m => m.id === mediaId);
    if (mediaItem) {
        broadcastToDevices(validDeviceIds, {
            type: 'announcement',
            announcement: announcement,
            media: mediaItem,
            timestamp: new Date()
        });
    }
    
    res.json(announcement);
});

app.put('/api/announcements/:id/cancel', authenticateToken, (req, res) => {
    const announcementId = req.params.id;
    const announcementIndex = announcements.findIndex(a => 
        a.id === announcementId && a.userId === req.user.id
    );
    
    if (announcementIndex === -1) {
        return res.status(404).json({ error: 'Pronunciamento não encontrado' });
    }
    
    announcements[announcementIndex].status = 'cancelled';
    saveData(DATA_FILES.announcements, announcements);
    
    // Notificar dispositivos sobre o cancelamento
    broadcastToDevices(announcements[announcementIndex].deviceIds, {
        type: 'announcement_cancelled',
        announcementId: announcementId,
        timestamp: new Date()
    });
    
    res.json({ message: 'Pronunciamento cancelado com sucesso' });
});

// ==================== ROTAS CLIENT TV ====================

app.get('/api/client/media', (req, res) => {
    const device = req.authorizedDevice;
    let mediaList = [];
    
    if (device.playlistId) {
        const playlist = playlists.find(p => p.id === device.playlistId);
        if (playlist) {
            // Usar ordem específica da playlist ou ordem padrão
            if (playlist.mediaOrder && playlist.mediaOrder.length > 0) {
                mediaList = playlist.mediaOrder.map(mediaId => 
                    media.find(m => m.id === mediaId)
                ).filter(Boolean);
            } else {
                mediaList = media.filter(m => playlist.mediaIds.includes(m.id));
                // Ordenar pela ordem definida
                mediaList.sort((a, b) => (a.order || 0) - (b.order || 0));
            }
        }
    } else {
        // Todas as mídias do usuário, ordenadas
        mediaList = media.filter(m => m.userId === device.userId);
        mediaList.sort((a, b) => (a.order || 0) - (b.order || 0));
    }
    
    res.json(mediaList);
});

// ADICIONAR: Rota para verificar se dispositivo foi ativado
app.post('/api/client/check-activation', (req, res) => {
    const { mac } = req.body;
    
    console.log(`🔍 Verificando ativação para MAC: ${mac}`);
    
    if (!mac) {
        return res.status(400).json({ error: 'MAC é obrigatório' });
    }
    
    // Buscar dispositivo pelo MAC
    const device = devices.find(d => d.mac === mac && d.status === 'active');
    
    if (device) {
        console.log(`✅ Dispositivo ${device.name} está ativado`);
        res.json({
            activated: true,
            device: {
                id: device.id,
                name: device.name,
                mac: device.mac,
                location: device.location,
                playlistId: device.playlistId,
                status: device.status
            }
        });
    } else {
        console.log(`❌ Dispositivo com MAC ${mac} não está ativado`);
        res.json({
            activated: false
        });
    }
});

// ATUALIZAR: Rota client device para aceitar MAC no body também
app.get('/api/client/device', (req, res) => {
    if (!req.authorizedDevice) {
        return res.status(403).json({ error: 'Dispositivo não autorizado' });
    }
    
    res.json(req.authorizedDevice);
});

// ADICIONAR: Rota alternativa para client device com MAC no body
app.post('/api/client/device', (req, res) => {
    const { mac } = req.body;
    
    if (!mac) {
        return res.status(400).json({ error: 'MAC é obrigatório' });
    }
    
    const device = devices.find(d => d.mac === mac && d.status === 'active');
    
    if (!device) {
        return res.status(403).json({ error: 'Dispositivo não autorizado ou não ativado' });
    }
    
    res.json(device);
});

// Servir arquivos
app.use('/media', express.static('uploads/media'));
app.use('/admin', express.static('../web-admin'));
app.use('/client', express.static('../tv-client'));
app.use('/', express.static('../landing-page'));
// Rota inicial
// app.get('/', (req, res) => {
//     res.redirect('/admin');
// });

app.get("/", (req, res) => 
   {
    let filePath = path.join(__dirname, '..', req.url === '/' ? 'index.html' : req.url);
    const ext = path.extname(filePath);

    fs.readFile(filePath, (err, content) => {
        if (err) {
            res.writeHead(404);
            res.end('Arquivo não encontrado');
        } else {
            let contentType = 'text/html';
            if (ext === '.js') contentType = 'text/javascript';
            if (ext === '.css') contentType = 'text/css';
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content);
        }
    });
});

// WebSocket server
const server = app.listen(PORT, '0.0.0.0', async () => {
    await initializeAdminUser();
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`📊 Admin: http://localhost:${PORT}/admin`);
    console.log(`📺 Client: http://localhost:${PORT}/client`);
    console.log(`🔗 WebSocket: ws://localhost:${PORT}`);
    console.log(`💾 Arquivos de dados: ${Object.values(DATA_FILES).join(', ')}`);
});

// Attach WebSocket to server
server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});

// WebSocket connection - ATUALIZADO para MAC
wss.on('connection', (ws, req) => {
    const clientIp = req.socket.remoteAddress.replace('::ffff:', '');
    console.log('🔗 WebSocket conectado:', clientIp);
    
    let clientDeviceId = null;
    let clientMac = null;
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            console.log('📨 Mensagem WebSocket recebida:', data.type, 'de:', data.deviceId);
            
            if (data.type === 'register') {
                clientDeviceId = data.deviceId;
                clientMac = data.mac;
                
                connectedClients.set(data.deviceId, {
                    ws: ws,
                    deviceId: data.deviceId,
                    mac: data.mac,
                    ip: clientIp,
                    lastPing: Date.now(),
                    currentMedia: null,
                    lastActivity: new Date()
                });
                
                console.log(`📱 Dispositivo ${data.deviceId} (MAC: ${data.mac}) registrado para WebSocket`);
                
                // Atualizar status do dispositivo
                const device = devices.find(d => d.id === data.deviceId);
                if (device) {
                    device.status = 'active';
                    device.lastSeen = new Date();
                    saveData(DATA_FILES.devices, devices);
                    console.log(`✅ Status do dispositivo ${device.name} atualizado para ativo`);
                }
            }
            
            if (data.type === 'ping') {
                const client = connectedClients.get(data.deviceId);
                if (client) {
                    client.lastPing = Date.now();
                    client.lastActivity = new Date();
                }
            }
            
            if (data.type === 'current_media') {
                const client = connectedClients.get(data.deviceId);
                if (client) {
                    client.currentMedia = data;
                    client.lastPing = Date.now();
                    client.lastActivity = new Date();
                }
                
                broadcastToAdmins({
                    type: 'device_media_update',
                    deviceId: data.deviceId,
                    mac: clientMac,
                    media: data.media,
                    currentMediaIndex: data.currentMediaIndex,
                    timestamp: new Date()
                });
            }

            if (data.type === 'request_preview') {
                const client = connectedClients.get(data.deviceId);
                if (client && client.ws.readyState === WebSocket.OPEN) {
                    client.ws.send(JSON.stringify({
                        type: 'send_preview',
                        timestamp: new Date()
                    }));
                }
            }
        } catch (error) {
            console.error('Erro WebSocket:', error);
        }
    });
    
    ws.on('close', (code, reason) => {
        console.log(`🔌 WebSocket desconectado: ${clientDeviceId} - Código: ${code}, Razão: ${reason}`);
        
        if (clientDeviceId) {
            connectedClients.delete(clientDeviceId);
            console.log(`📱 Dispositivo ${clientDeviceId} desconectado do WebSocket`);
            
            // NÃO alterar status para offline - manter ativo até desconexão administrativa
            const device = devices.find(d => d.id === clientDeviceId);
            if (device) {
                console.log(`📴 Dispositivo ${device.name} desconectado, mas mantendo status ativo`);
                // Apenas atualizar lastSeen, manter status ativo
                device.lastSeen = new Date();
                saveData(DATA_FILES.devices, devices);
            }
        }
    });
    
    ws.on('error', (error) => {
        console.error('❌ Erro WebSocket:', error);
        if (clientDeviceId) {
            connectedClients.delete(clientDeviceId);
        }
    });
    
    // Heartbeat para manter conexão ativa
    const heartbeatInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.ping(); // WebSocket ping
        } else {
            clearInterval(heartbeatInterval);
        }
    }, 30000);
    
    ws.on('pong', () => {
        // Conexão está ativa
        if (clientDeviceId) {
            const client = connectedClients.get(clientDeviceId);
            if (client) {
                client.lastPing = Date.now();
            }
        }
    });
});

// Função para broadcast para admins
function broadcastToAdmins(message) {
    connectedClients.forEach((client, deviceId) => {
        // Enviar apenas para clientes que são admins (baseado no IP ou outro critério)
        // Por enquanto, enviar para todos os clientes conectados
        if (client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify(message));
        }
    });
}

// Função para broadcast para dispositivos específicos
function broadcastToDevices(deviceIds, message) {
    console.log(`📤 Broadcast para ${deviceIds.length} dispositivos:`, message.type);
    
    // Log para debug de loops
    if (message.type === 'sync_command') {
        console.log('🔧 Sync Command Details:', {
            playlistId: message.playlistId,
            currentMediaIndex: message.currentMediaIndex,
            timestamp: new Date().toISOString()
        });
    }
    
    let connectedCount = 0;
    
    deviceIds.forEach(deviceId => {
        const client = connectedClients.get(deviceId);
        if (client && client.ws.readyState === WebSocket.OPEN) {
            console.log(`✅ Enviando ${message.type} para dispositivo ${deviceId}`);
            client.ws.send(JSON.stringify(message));
            connectedCount++;
        } else {
            console.log(`❌ Dispositivo ${deviceId} não conectado`);
        }
    });
    
    console.log(`📊 ${message.type} enviada para ${connectedCount}/${deviceIds.length} dispositivos`);
    return connectedCount;
}

// Inicializar com usuário admin
async function initializeAdminUser() {
    if (users.length === 0) {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        const adminUser = {
            id: '1',
            username: 'admin',
            password: hashedPassword,
            name: 'Administrador',
            role: 'admin',
            createdAt: new Date(),
            lastLogin: null,
            token: null
        };
        users.push(adminUser);
        saveData(DATA_FILES.users, users);
        console.log('👑 Usuário admin criado: admin / admin123');
    }
}

// ==================== FUNÇÕES AUXILIARES PARA SINCRONIZAÇÃO ====================

function calculatePlaylistDuration(playlistIndex) {
    const playlist = playlists[playlistIndex];
    let totalDuration = 0;
    
    playlist.mediaIds.forEach(mediaId => {
        const mediaItem = media.find(m => m.id === mediaId);
        if (mediaItem) {
            totalDuration += (mediaItem.displayTime || 10) * 1000;
        }
    });
    
    return totalDuration;
}

// Função de sincronização OTIMIZADA para servidor local
function calculateExactSyncData(playlistIndex, targetMediaIndex = 0) {
    const playlist = playlists[playlistIndex];
    const syncTime = new Date().toISOString();
    
    let currentMediaIndex = targetMediaIndex;
    let elapsedPlaylistTime = 0;
    let currentMediaDuration = 0;
    let remainingTime = 0;
    
    // Calcular tempo decorrido na playlist - OTIMIZADO
    for (let i = 0; i < playlist.mediaIds.length; i++) {
        const mediaId = playlist.mediaIds[i];
        const mediaItem = media.find(m => m.id === mediaId);
        
        if (mediaItem) {
            const mediaDuration = (mediaItem.displayTime || 10) * 1000;
            
            if (i < targetMediaIndex) {
                // Mídias já passadas
                elapsedPlaylistTime += mediaDuration;
            } else if (i === targetMediaIndex) {
                // Mídia atual - COMEÇAR SEMPRE DO ZERO para sincronização precisa
                currentMediaDuration = mediaDuration;
                remainingTime = mediaDuration; // Tempo total da mídia
                break;
            }
        }
    }
    
    return {
        currentMediaIndex: currentMediaIndex,
        mediaStartTime: syncTime, // Todas começam no mesmo tempo
        syncTime: syncTime,
        totalPlaylistDuration: calculatePlaylistDuration(playlistIndex),
        currentMediaDuration: currentMediaDuration,
        remainingTime: remainingTime,
        elapsedPlaylistTime: elapsedPlaylistTime
    };
}

// Adicionar rota para limpeza de códigos expirados
setInterval(() => {
    const now = new Date();
    let cleanedCount = 0;
    
    devices.forEach(device => {
        if (device.status === 'pending' && device.codeExpiry && new Date(device.codeExpiry) < now) {
            // Gerar novo código para dispositivos pendentes com código expirado
            device.authCode = Math.floor(100000 + Math.random() * 900000).toString();
            device.codeExpiry = new Date(Date.now() + 5 * 60 * 1000).toISOString();
            device.lastCodeUpdate = new Date();
            cleanedCount++;
        }
    });
    
    if (cleanedCount > 0) {
        saveData(DATA_FILES.devices, devices);
        console.log(`🧹 ${cleanedCount} código(s) expirado(s) renovado(s)`);
    }
}, 60000); // Verificar a cada minuto

console.log('🔄 Sistema de renovação de códigos expirados iniciado');

// REMOVER limpeza periódica de dispositivos inativos (agora queremos persistência)
// Apenas manter lastSeen atualizado quando dispositivos se conectarem

// Adicionar rota para debug de dispositivos por MAC
app.get('/api/debug/devices-mac', (req, res) => {
    res.json({
        totalDevices: devices.length,
        activeDevices: devices.filter(d => d.status === 'active'),
        pendingDevices: devices.filter(d => d.status === 'pending'),
        allDevices: devices.map(d => ({
            id: d.id,
            name: d.name,
            mac: d.mac,
            status: d.status,
            authCode: d.authCode,
            codeExpiry: d.codeExpiry,
            location: d.location,
            lastSeen: d.lastSeen
        }))
    });
});