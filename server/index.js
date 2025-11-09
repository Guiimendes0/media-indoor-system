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

// Middleware de autenticação - CORRIGIDO
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

// Middleware para dispositivo autorizado - CORRIGIDA para ignorar arquivos de mídia
function checkDeviceAuthorization(req, res, next) {
    // IGNORAR requisições para arquivos de mídia
    if (req.path.startsWith('/media/')) {
        return next(); // Pular verificação para arquivos de mídia
    }
    
    let clientIp = req.ip || req.connection.remoteAddress;
    
    // CORREÇÃO: Verificar se clientIp existe antes de usar .replace()
    if (!clientIp) {
        console.log('❌ IP do cliente não detectado');
        clientIp = 'unknown';
    } else {
        // Limpar e normalizar o IP apenas se não for undefined
        clientIp = clientIp.replace('::ffff:', '').replace('::1', '127.0.0.1');
    }
    
    console.log(`🔍 Verificando autorização para IP: ${clientIp} - Rota: ${req.path}`);
    
    // Aplicar verificação APENAS para rotas de API do cliente
    if (req.path.startsWith('/api/client/')) {
        console.log('🔐 Rota cliente detectada, verificando dispositivos...');
        
        // Buscar dispositivo por IP EXATO primeiro
        let authorizedDevice = devices.find(device => 
            device.ip === clientIp && device.status === 'active'
        );
        
        // Se não encontrou por IP exato, tentar match parcial (para casos de proxy)
        if (!authorizedDevice) {
            console.log(`❌ IP exato não encontrado, tentando match parcial...`);
            authorizedDevice = devices.find(device => {
                // CORREÇÃO: Verificar se device.ip existe antes de comparar
                if (!device.ip) return false;
                
                const ipMatch = clientIp.includes(device.ip) || 
                               (device.ip && device.ip.includes(clientIp));
                return ipMatch && device.status === 'active';
            });
        }
        
        if (!authorizedDevice) {
            console.log('❌ Acesso negado para IP:', clientIp);
            console.log('📊 Dispositivos cadastrados ativos:');
            devices.filter(d => d.status === 'active').forEach(device => {
                console.log(`   - ${device.name}: ${device.ip} (${device.status})`);
            });
            
            return res.status(403).json({ 
                error: 'Dispositivo não autorizado',
                message: `IP ${clientIp} não está cadastrado como dispositivo ativo`,
                detectedIp: clientIp,
                registeredDevices: devices.filter(d => d.status === 'active').map(d => ({ name: d.name, ip: d.ip }))
            });
        }
        
        authorizedDevice.lastSeen = new Date();
        saveData(DATA_FILES.devices, devices);
        
        console.log('✅ Acesso autorizado para:', authorizedDevice.name, `IP: ${clientIp}`);
        req.authorizedDevice = authorizedDevice;
    }
    
    next();
}

app.use(checkDeviceAuthorization);
// ADICIONAR este middleware para debug de todas as requisições - CORRIGIDO
app.use((req, res, next) => {
    // Não logar requisições para arquivos de mídia para evitar spam
    if (!req.path.startsWith('/media/') && !req.path.startsWith('/admin/') && !req.path.startsWith('/client/')) {
        const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
        console.log(`🌐 ${req.method} ${req.path} - IP: ${clientIp}`);
    }
    next();
});


// WebSocket connection
wss.on('connection', (ws, req) => {
    const clientIp = req.socket.remoteAddress.replace('::ffff:', '');
    console.log('🔗 WebSocket conectado:', clientIp);
    
    // Armazenar informações do cliente
    let clientDeviceId = null;
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            console.log('📨 Mensagem WebSocket recebida:', data);
            
            if (data.type === 'register') {
                // Registrar cliente para sincronização/visualização
                clientDeviceId = data.deviceId;
                connectedClients.set(data.deviceId, {
                    ws: ws,
                    deviceId: data.deviceId,
                    ip: clientIp,
                    lastPing: Date.now(),
                    currentMedia: null
                });
                console.log(`📱 Dispositivo ${data.deviceId} registrado para WebSocket`);
            }
            
            if (data.type === 'ping') {
                // Atualizar ping
                const client = connectedClients.get(data.deviceId);
                if (client) {
                    client.lastPing = Date.now();
                }
            }
            
            if (data.type === 'current_media') {
                // Atualizar informação da mídia atual
                const client = connectedClients.get(data.deviceId);
                if (client) {
                    client.currentMedia = data;
                    client.lastPing = Date.now();
                }
                
                // Broadcast da mídia atual para visualização (apenas para admins)
                broadcastToAdmins({
                    type: 'device_media_update',
                    deviceId: data.deviceId,
                    media: data.media,
                    currentMediaIndex: data.currentMediaIndex,
                    timestamp: new Date()
                });
            }

            if (data.type === 'request_preview') {
                // Solicitação de preview - enviar para o dispositivo específico
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
    
    ws.on('close', () => {
        // Remover cliente desconectado
        if (clientDeviceId) {
            connectedClients.delete(clientDeviceId);
            console.log(`📱 Dispositivo ${clientDeviceId} desconectado do WebSocket`);
        }
    });
    
    ws.on('error', (error) => {
        console.error('❌ Erro WebSocket:', error);
        if (clientDeviceId) {
            connectedClients.delete(clientDeviceId);
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

// Função para broadcast para dispositivos específicos - CORRIGIDA
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

// WebSocket connection - CORRIGIDO para melhor reconexão
wss.on('connection', (ws, req) => {
    const clientIp = req.socket.remoteAddress.replace('::ffff:', '');
    console.log('🔗 WebSocket conectado:', clientIp);
    
    // Armazenar informações do cliente
    let clientDeviceId = null;
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            console.log('📨 Mensagem WebSocket recebida:', data.type, 'de:', data.deviceId);
            
            if (data.type === 'register') {
                // Registrar cliente para sincronização/visualização
                clientDeviceId = data.deviceId;
                connectedClients.set(data.deviceId, {
                    ws: ws,
                    deviceId: data.deviceId,
                    ip: clientIp,
                    lastPing: Date.now(),
                    currentMedia: null,
                    lastActivity: new Date()
                });
                console.log(`📱 Dispositivo ${data.deviceId} registrado para WebSocket`);
                
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
                // Atualizar ping
                const client = connectedClients.get(data.deviceId);
                if (client) {
                    client.lastPing = Date.now();
                    client.lastActivity = new Date();
                }
            }
            
            if (data.type === 'current_media') {
                // Atualizar informação da mídia atual
                const client = connectedClients.get(data.deviceId);
                if (client) {
                    client.currentMedia = data;
                    client.lastPing = Date.now();
                    client.lastActivity = new Date();
                }
                
                // Broadcast da mídia atual para visualização (apenas para admins)
                broadcastToAdmins({
                    type: 'device_media_update',
                    deviceId: data.deviceId,
                    media: data.media,
                    currentMediaIndex: data.currentMediaIndex,
                    timestamp: new Date()
                });
            }

            if (data.type === 'request_preview') {
                // Solicitação de preview - enviar para o dispositivo específico
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
        // Remover cliente desconectado
        if (clientDeviceId) {
            connectedClients.delete(clientDeviceId);
            console.log(`📱 Dispositivo ${clientDeviceId} desconectado do WebSocket`);
            
            // Atualizar status do dispositivo
            const device = devices.find(d => d.id === clientDeviceId);
            if (device) {
                device.status = 'offline';
                saveData(DATA_FILES.devices, devices);
                console.log(`📴 Status do dispositivo ${device.name} atualizado para offline`);
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
    res.json(userDevices);
});

app.post('/api/devices', authenticateToken, (req, res) => {
    const { name, ip, location, playlistId } = req.body;
    
    if (devices.find(d => d.ip === ip)) {
        return res.status(400).json({ error: 'IP já cadastrado' });
    }
    
    const authCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    const device = {
        id: Date.now().toString(),
        name,
        ip,
        location,
        playlistId: playlistId || null,
        userId: req.user.id,
        authCode,
        status: 'pending',
        lastSeen: null,
        createdAt: new Date()
    };
    
    devices.push(device);
    saveData(DATA_FILES.devices, devices);
    res.json(device);
});

app.put('/api/devices/:id', authenticateToken, (req, res) => {
    const deviceId = req.params.id;
    const { name, ip, location, playlistId } = req.body;
    
    const deviceIndex = devices.findIndex(device => 
        device.id === deviceId && (device.userId === req.user.id || req.user.role === 'admin')
    );
    
    if (deviceIndex === -1) {
        return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }
    
    // Verificar se o IP já está em uso por outro dispositivo
    if (ip && ip !== devices[deviceIndex].ip) {
        const existingDevice = devices.find(d => d.ip === ip && d.id !== deviceId);
        if (existingDevice) {
            return res.status(400).json({ error: 'IP já está em uso por outro dispositivo' });
        }
    }
    
    devices[deviceIndex] = {
        ...devices[deviceIndex],
        name: name || devices[deviceIndex].name,
        ip: ip || devices[deviceIndex].ip,
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


// Ativar dispositivo - ADICIONAR logs
// Ativar dispositivo - CORRIGIDA com validação de IP
app.post('/api/devices/activate', (req, res) => {
    const { ip, authCode } = req.body;
    
    // CORREÇÃO: Validar se IP foi fornecido
    if (!ip) {
        console.log('❌ Tentativa de ativação sem IP');
        return res.status(400).json({ error: 'IP não fornecido' });
    }
    
    console.log(`🔐 Tentativa de ativação - IP: ${ip}, Código: ${authCode}`);
    console.log('📋 Dispositivos disponíveis:', devices.map(d => `${d.name} (${d.ip} - ${d.authCode})`));
    
    const device = devices.find(d => d.ip === ip && d.authCode === authCode);
    if (!device) {
        console.log(`❌ Ativação falhou - IP: ${ip}, Código: ${authCode} não encontrado`);
        return res.status(400).json({ error: 'Código de autenticação inválido' });
    }
    
    device.status = 'active';
    device.lastSeen = new Date();
    saveData(DATA_FILES.devices, devices);
    
    console.log(`✅ Dispositivo ativado: ${device.name} (${device.ip})`);
    
    res.json({ 
        message: 'Dispositivo ativado com sucesso',
        device: {
            name: device.name,
            location: device.location,
            id: device.id
        }
    });
});

// ADICIONAR este middleware para debug de todas as requisições
app.use((req, res, next) => {
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
    console.log(`🌐 ${req.method} ${req.path} - IP: ${clientIp}`);
    next();
});

// ==================== ROTAS DE SINCRONIZAÇÃO POR PLAYLIST ====================

app.post('/api/playlists/:id/sync', authenticateToken, (req, res) => {
    const playlistId = req.params.id;
    
    const playlistIndex = playlists.findIndex(p => 
        p.id === playlistId && (p.userId === req.user.id || req.user.role === 'admin')
    );
    
    if (playlistIndex === -1) {
        return res.status(404).json({ error: 'Playlist não encontrada' });
    }
    
    const { currentMediaIndex = 0 } = req.body;
    
    // Encontrar todos os dispositivos ativos que usam esta playlist
    const devicesUsingPlaylist = devices.filter(device => 
        device.playlistId === playlistId && device.status === 'active'
    );
    
    const deviceIds = devicesUsingPlaylist.map(device => device.id);
    
    if (deviceIds.length === 0) {
        return res.status(400).json({ error: 'Nenhum dispositivo ativo usando esta playlist' });
    }
    
    // Calcular tempo EXATO para cada dispositivo - SEMPRE COMEÇAR DO ZERO
    const syncData = {
        currentMediaIndex: currentMediaIndex,
        mediaStartTime: new Date().toISOString(), // Começar AGORA
        syncTime: new Date().toISOString(),
        totalPlaylistDuration: calculatePlaylistDuration(playlistIndex),
        currentMediaDuration: 0,
        remainingTime: 0,
        elapsedPlaylistTime: 0
    };
    
    // Calcular tempo real baseado no índice atual
    if (currentMediaIndex > 0) {
        let elapsedTime = 0;
        for (let i = 0; i < currentMediaIndex; i++) {
            const mediaId = playlists[playlistIndex].mediaIds[i];
            const mediaItem = media.find(m => m.id === mediaId);
            if (mediaItem) {
                elapsedTime += (mediaItem.displayTime || 10) * 1000;
            }
        }
        syncData.elapsedPlaylistTime = elapsedTime;
    }
    
    // Se tem mídia atual, calcular sua duração
    if (playlists[playlistIndex].mediaIds[currentMediaIndex]) {
        const currentMediaId = playlists[playlistIndex].mediaIds[currentMediaIndex];
        const mediaItem = media.find(m => m.id === currentMediaId);
        if (mediaItem) {
            syncData.currentMediaDuration = (mediaItem.displayTime || 10) * 1000;
            syncData.remainingTime = syncData.currentMediaDuration; // Começar do início da mídia
        }
    }
    
    // Atualizar informações de sincronização da playlist
    playlists[playlistIndex].syncInfo = {
        currentMediaIndex: currentMediaIndex,
        mediaStartTime: syncData.mediaStartTime,
        syncTime: syncData.syncTime,
        totalPlaylistDuration: syncData.totalPlaylistDuration,
        lastSync: new Date().toISOString(),
        syncBy: req.user.id
    };
    
    saveData(DATA_FILES.playlists, playlists);
    
    // Broadcast para dispositivos com TODOS os parâmetros
    broadcastToDevices(deviceIds, {
        type: 'sync_command',
        command: 'sync_playlist',
        playlistId: playlistId,
        currentMediaIndex: syncData.currentMediaIndex,
        mediaStartTime: syncData.mediaStartTime,
        syncTime: syncData.syncTime,
        totalPlaylistDuration: syncData.totalPlaylistDuration,
        currentMediaDuration: syncData.currentMediaDuration,
        remainingTime: syncData.remainingTime,
        elapsedPlaylistTime: syncData.elapsedPlaylistTime,
        timestamp: new Date().toISOString()
    });
    
    console.log(`🔄 Playlist ${playlistId} sincronizada. Dispositivos: ${deviceIds.join(', ')}`);
    
    res.json({ 
        message: `Playlist sincronizada para ${deviceIds.length} dispositivo(s)`,
        playlistId: playlistId,
        deviceIds: deviceIds,
        syncInfo: syncData
    });
});

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

app.post('/api/playlists', authenticateToken, (req, res) => {
    const { name, mediaIds, schedule, mediaOrder = [] } = req.body;
    
    // Verificar se as mídias pertencem ao usuário
    const userMediaIds = media.filter(m => m.userId === req.user.id).map(m => m.id);
    const validMediaIds = mediaIds.filter(id => userMediaIds.includes(id));
    
    const playlist = {
        id: Date.now().toString(),
        name,
        mediaIds: validMediaIds,
        mediaOrder: mediaOrder, // Ordem específica da playlist
        schedule: schedule || {},
        userId: req.user.id,
        createdAt: new Date()
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
    
    playlists[playlistIndex] = {
        ...playlists[playlistIndex],
        name: name || playlists[playlistIndex].name,
        mediaIds: validMediaIds,
        mediaOrder: mediaOrder || playlists[playlistIndex].mediaOrder,
        schedule: schedule || playlists[playlistIndex].schedule
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

app.get('/api/client/device', (req, res) => {
    res.json(req.authorizedDevice);
});

// Servir arquivos
app.use('/media', express.static('uploads/media'));
app.use('/admin', express.static('../web-admin'));
app.use('/client', express.static('../tv-client'));

// Rota inicial
app.get('/', (req, res) => {
    res.redirect('/admin');
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

// Limpeza periódica de dispositivos inativos (opcional)
setInterval(() => {
    const now = new Date();
    const inactiveThreshold = 30 * 60 * 1000; // 30 minutos
    
    devices.forEach(device => {
        if (device.status === 'active' && device.lastSeen) {
            const lastSeen = new Date(device.lastSeen);
            if (now - lastSeen > inactiveThreshold) {
                console.log(`🔌 Dispositivo ${device.name} marcado como inativo`);
                device.status = 'inactive';
            }
        }
    });
    
    saveData(DATA_FILES.devices, devices);
}, 5 * 60 * 1000); // Verificar a cada 5 minutos

console.log('🔄 Sistema de limpeza de dispositivos inativos iniciado');


// ==================== FUNÇÕES AUXILIARES PARA SINCRONIZAÇÃO OTIMIZADAS ====================

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

// ==================== ROTAS DE SINCRONIZAÇÃO POR PLAYLIST OTIMIZADAS ====================

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
    
    const { currentMediaIndex = 0 } = req.body;
    console.log(`📊 Sincronizando a partir da mídia índice: ${currentMediaIndex}`);
    
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
    
    // SINCRONIZAÇÃO OTIMIZADA - TEMPO REAL
    const syncTime = new Date().toISOString();
    const syncData = calculateExactSyncData(playlistIndex, currentMediaIndex);
    
    // Atualizar tempo de início para AGORA
    syncData.mediaStartTime = syncTime;
    syncData.syncTime = syncTime;
    
    console.log(`📈 Dados de sincronização otimizados:`, syncData);
    
    // Atualizar informações de sincronização da playlist
    playlists[playlistIndex].syncInfo = {
        currentMediaIndex: currentMediaIndex,
        mediaStartTime: syncData.mediaStartTime,
        syncTime: syncData.syncTime,
        totalPlaylistDuration: syncData.totalPlaylistDuration,
        lastSync: new Date().toISOString(),
        syncBy: req.user.id
    };
    
    saveData(DATA_FILES.playlists, playlists);
    
    // Broadcast OTIMIZADO - enviar imediatamente
    console.log(`📤 Enviando sincronização para dispositivos: ${deviceIds.join(', ')}`);
    
    // Enviar com timestamp de alta precisão
    const syncMessage = {
        type: 'sync_command',
        command: 'sync_playlist',
        playlistId: playlistId,
        currentMediaIndex: syncData.currentMediaIndex,
        mediaStartTime: syncData.mediaStartTime,
        syncTime: syncData.syncTime,
        totalPlaylistDuration: syncData.totalPlaylistDuration,
        currentMediaDuration: syncData.currentMediaDuration,
        remainingTime: syncData.remainingTime,
        elapsedPlaylistTime: syncData.elapsedPlaylistTime,
        timestamp: new Date().toISOString(),
        serverTime: Date.now() // Timestamp de alta precisão
    };
    
    broadcastToDevices(deviceIds, syncMessage);
    
    console.log(`✅ Playlist ${playlistId} sincronizada com alta precisão!`);
    
    res.json({ 
        message: `Playlist sincronizada para ${deviceIds.length} dispositivo(s)`,
        playlistId: playlistId,
        deviceIds: deviceIds,
        syncInfo: syncData,
        serverTime: Date.now()
    });
});

// Adicionar rota para debug de dispositivos
app.get('/api/debug/devices', (req, res) => {
    res.json({
        totalDevices: devices.length,
        activeDevices: devices.filter(d => d.status === 'active'),
        allDevices: devices.map(d => ({
            name: d.name,
            ip: d.ip,
            status: d.status,
            authCode: d.authCode,
            location: d.location
        }))
    });
});