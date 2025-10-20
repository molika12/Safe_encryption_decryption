const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const Sender = require('./models/Sender'); // Your schema file
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const fetch = require('node-fetch'); // Use node-fetch for v2

const app = express();

// --- Middleware ---
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// --- File Upload Setup ---
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// --- MongoDB Atlas connection ---
const MONGO_URI = process.env.MONGO_URI;mongoose.connect(MONGO_URI, { 
    dbName: "secureShareDB",
   
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// --- Nodemailer transporter ---
const transporter = nodemailer.createTransport({
  service: 'gmail',
auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },   
});

// --- ROUTES ---

// --- Fetch receivers ---
app.get('/receivers/:senderId', async (req, res) => {
    try {
        const { email } = req.query;
        const sender = await Sender.findOne({ uniqueId: req.params.senderId }); 
        if (!sender) return res.json({ success: false, message: 'Sender not found' });

        let receivers = sender.receivers;
        if (email) receivers = receivers.filter(r => r.email === email);
        res.json({ success: true, receivers });
    } catch (err) {
        console.error(err);
        res.json({ success: false, message: 'Server error' });
    }
});

// --- Signup ---
app.post('/signup', async (req, res) => {
    const { role, email, password, linkedSender } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        if (role === 'sender') {
            const uniqueId = uuidv4();
            const sender = new Sender({ email, password: hashedPassword, uniqueId });
            await sender.save();
            return res.json({ success: true, uniqueId });
        } else {
            const sender = await Sender.findOne({ uniqueId: linkedSender }); 
            if (!sender) return res.json({ success: false, message: 'Invalid Sender ID' });

            sender.receivers.push({ email, password: hashedPassword, keys: [] }); 
            await sender.save();
            return res.json({ success: true });
        }
    } catch (err) {
        console.error(err);
        if (err.code === 11000) return res.json({ success: false, message: 'Email or ID already exists' });
        res.json({ success: false, message: 'Server error' });
    }
});

// --- UNIFIED LOGIN ROUTE ---
app.post('/login', async (req, res) => {
    const { role, email, password, senderId } = req.body;
  
    try {
      if (role === 'sender') {
        const sender = await Sender.findOne({ email });
        if (!sender) return res.json({ success: false, message: 'Sender not found' });
        if (!password) return res.json({ success: false, message: 'Password required' });
  
        const match = await bcrypt.compare(password, sender.password);
        if (!match) return res.json({ success: false, message: 'Incorrect password' });
  
        return res.json({ success: true, uniqueId: sender.uniqueId, userName: sender.email });
  
      } else if (role === 'receiver') {
        const sender = await Sender.findOne({ uniqueId: senderId });
        if (!sender) {
            return res.json({ success: false, message: 'Sender ID not found' });
        }
  
        const receiver = sender.receivers.find(r => r.email === email);
        if (!receiver) {
            return res.json({ success: false, message: 'Receiver email not found for that Sender ID' });
        }
  
        return res.json({ 
            success: true, 
            senderId: sender.uniqueId, // Send the uniqueId
            receiverId: receiver._id,
            keys: receiver.keys || [] 
        });
  
      } else {
        return res.json({ success: false, message: 'Invalid role' });
      }
  
    } catch (err) {
      console.error(err);
      res.json({ success: false, message: 'Server error' });
    }
  });

// --- Add receiver ---
app.post('/add-user', async (req, res) => {
    const { senderId, email, password } = req.body;
    if (!senderId || !email || !password) {
        return res.json({ success: false, message: 'All fields are required' });
    }

    try {
        const sender = await Sender.findOne({ uniqueId: senderId });
        if (!sender) return res.json({ success: false, message: 'Sender not found' });

        const existingReceiver = sender.receivers.find(r => r.email === email);
        if (existingReceiver) return res.json({ success: false, message: 'Receiver already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        sender.receivers.push({ email, password: hashedPassword });
        await sender.save();

        const mailOptions = {
            from: "molika_y@srmap.edu.in",
            to: email,
            subject: `🎉 Welcome to SecureShare, ${email}!`,
            text: `Hello ${email},\n\nWelcome to SecureShare!\nYour Sender ID: ${sender.uniqueId}\n...`
        };

        await transporter.sendMail(mailOptions);
        res.json({ success: true, message: 'User added and email sent' });
    } catch (err) {
        console.error('Error in /add-user:', err);
        res.json({ success: false, message: 'An error occurred while adding the user or sending mail' });
    }
});


// --- Delete receiver ---
app.delete('/delete-receiver', async (req, res) => {
    const { senderId, receiverEmail } = req.body; 
    try {
        const sender = await Sender.findOne({ uniqueId: senderId }); 
        if (!sender) return res.json({ success: false, message: 'Sender not found' });

        const index = sender.receivers.findIndex(r => r.email === receiverEmail);
        if (index === -1) return res.json({ success: false, message: 'Receiver not found' });

        sender.receivers.splice(index, 1);
        await sender.save();
        res.json({ success: true, message: 'Receiver deleted' });
    } catch (err) {
        console.error(err);
        res.json({ success: false, message: 'Server error' });
    }
});


// --- Encrypt route ---
// --- Encrypt route ---
app.post('/encrypt', upload.single('image'), async (req, res) => {
    const { receiverId } = req.body;
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    if (!receiverId) return res.status(400).json({ error: 'Receiver ID missing' });

    // --- IMPORTANT ---
    // Keep track of file paths to clean up properly
    const originalFilePath = req.file.path;
    let encFilePath = ''; // We'll set this later

    try {
        const sender = await Sender.findOne({ 'receivers._id': receiverId }); 
        if (!sender) return res.status(400).json({ error: 'Receiver not found' });

        const rIndex = sender.receivers.findIndex(r => r._id.toString() === receiverId);
        if (rIndex === -1) return res.status(400).json({ error: 'Receiver not found' });
        
        console.log('Encrypting for receiver:', sender.receivers[rIndex].email);

        const form = new FormData();
        form.append('image', fs.createReadStream(originalFilePath)); // Use the original path

        const flaskResponse = await axios.post('https://api-py-deploy.onrender.com/encrypt', form, {
            headers: form.getHeaders(),
        });

        const { encrypted_image_b64, hashes, seeds } = flaskResponse.data;
        if (!encrypted_image_b64 || !hashes || !seeds) {
             return res.status(500).json({ error: "Python server returned invalid data" });
        }
        
        const encryptedBuffer = Buffer.from(encrypted_image_b64, 'base64');
        
        // This is the filename you store in the DB
        const encFileName = 'enc_' + req.file.filename + '.png'; 
        
        // This is the full path to the file on your server
        encFilePath = path.join(uploadDir, encFileName); 
        fs.writeFileSync(encFilePath, encryptedBuffer);

        const authData = { seeds: seeds, hashes: hashes };
        const authDataString = JSON.stringify(authData);

        const keyObj = {
            image: req.file.originalname,
            encryptedImage: encFileName, // This is the name from the DB
            key: Date.now().toString(16), 
            hash: authDataString, 
            code_sent: "N/A", 
            createdAt: new Date()
        };

        sender.receivers[rIndex].keys.push(keyObj);
        await sender.save();
        console.log('✅ Keys saved in MongoDB');
        
        // --- THIS IS THE FIX ---
        // Instead of res.json(...), send the file for download.
        // 1st arg: The full path to the file on your server.
        // 2nd arg: The filename you want the user's browser to save it as.
        
        console.log(`🚀 Sending file ${encFileName} for download...`);
        res.download(encFilePath, encFileName, (err) => {
            if (err) {
                console.error('Error sending file:', err);
            }
            // After the download is sent (or if it fails),
            // delete the encrypted file from the server.
            console.log(`🧹 Cleaning up encrypted file: ${encFilePath}`);
            if (fs.existsSync(encFilePath)) {
                fs.unlinkSync(encFilePath);
            }
        });
        // --- END OF FIX ---

    } catch (err) {
        console.error('Encryption processing error:', err.response ? err.response.data : err.message);
        res.status(500).json({ error: 'Encryption failed. Please try again.' });
    } finally {
        // ALWAYS delete the *original* uploaded file, regardless of success or failure
        if (fs.existsSync(originalFilePath)) {
            console.log(`🧹 Cleaning up original file: ${originalFilePath}`);
            fs.unlinkSync(originalFilePath);
        }
    }
});

// --- Decrypt route ---
app.post("/decrypt", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No image uploaded" });
    const hashes = req.body.hashes; 
    if (!hashes) return res.status(400).json({ error: "Hashes/Seed data missing" });

    const form = new FormData();
    form.append("image", fs.createReadStream(req.file.path));
    form.append("hashes", hashes); 

    const flaskResponse = await fetch("https://api-py-deploy.onrender.com/decrypt", {
      method: "POST",
      body: form
    });

    if (!flaskResponse.ok) {
      const err = await flaskResponse.json();
      return res.status(flaskResponse.status).json(err);
    }

    const buffer = await flaskResponse.buffer();
    res.set({
      "Content-Type": "image/png",
      "Content-Disposition": `attachment; filename="decrypted_image.png"`
 });
    res.send(buffer);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  } finally {
        if (req.file) fs.unlinkSync(req.file.path);
  }
});

// --- SENDER DASHBOARD DATA ENDPOINT ---
app.get('/dashboard-data/:senderId', async (req, res) => {
    try {
        const senderUniqueId = req.params.senderId;
        const sender = await Sender.findOne({ uniqueId: senderUniqueId });

        if (!sender) {
            return res.status(404).json({ success: false, message: 'Sender not found' });
        }

        let totalFiles = 0;
        let recentFiles = [];

        sender.receivers.forEach(receiver => {
            receiver.keys.forEach(key => {
                totalFiles++;
                recentFiles.push({
                    name: key.image,
                    date: key.createdAt.toISOString().split('T')[0], 
                    size: "N/A",
                    status: "active",
                    downloads: 0,
                    receiverEmail: receiver.email,
                    encryptedImage: key.encryptedImage
                });
            });
        });

        recentFiles.sort((a, b) => new Date(b.date) - new Date(a.date));
        recentFiles = recentFiles.slice(0, 10);

        const dashboardData = {
            totalFiles: totalFiles,
            pendingRequests: 0, // Placeholder
            totalDownloads: 0,  // Placeholder
            files: recentFiles
        };

        res.json({ success: true, data: dashboardData });

    } catch (err) {
        console.error('Error fetching dashboard data:', err);
        res.status(500).json({ success: false, message: 'Server error fetching dashboard data' });
    }
});


// --- Receiver makes a file request ---
app.post('/request-file', async (req, res) => {
    const { senderId, receiverEmail } = req.body;
    if (!senderId || !receiverEmail) {
        return res.status(400).json({ success: false, message: 'Missing sender ID or receiver email' });
    }
    try {
        const sender = await Sender.findOne({ uniqueId: senderId });
        if (!sender) {
            return res.status(404).json({ success: false, message: 'Sender not found' });
        }
        const receiverIndex = sender.receivers.findIndex(r => r.email === receiverEmail);
        if (receiverIndex === -1) {
            return res.status(404).json({ success: false, message: 'Receiver not found' });
        }

        sender.receivers[receiverIndex].fileRequest = {
            status: 'pending',
            requestedAt: new Date(),
            approvedFileUrl: null,
            approvedFileName: null,
            approvedAt: null
        };
        await sender.save();
        console.log(`✅ New file request from ${receiverEmail} to sender ${senderId}`);
        res.json({ success: true, message: 'File request sent successfully.' });
    } catch (error) {
        console.error("Error sending file request:", error);
        res.status(500).json({ success: false, message: 'Server error while sending file request.' });
    }
});


// --- Receiver checks their request status ---
app.get('/check-request-status/:senderId/:receiverEmail', async (req, res) => {
    const { senderId, receiverEmail } = req.params;
     if (!senderId || !receiverEmail) {
        return res.status(400).json({ success: false, message: 'Missing sender ID or receiver email' });
    }
    try {
         const sender = await Sender.findOne({ uniqueId: senderId });
        if (!sender) {
            return res.status(404).json({ success: false, message: 'Sender not found' });
        }
         const receiver = sender.receivers.find(r => r.email === receiverEmail);
        if (!receiver) {
            return res.status(404).json({ success: false, message: 'Receiver not found' });
        }
        const fileRequestData = receiver.fileRequest || { status: 'idle' };
        res.json({ success: true, fileRequest: fileRequestData });
    } catch (error) {
         console.error("Error checking request status:", error);
        res.status(500).json({ success: false, message: 'Server error checking status' });
    }
});

// --- Receiver cancels their *pending* request ---
app.post('/cancel-request', async (req, res) => {
    const { senderId, receiverEmail } = req.body;
    if (!senderId || !receiverEmail) {
        return res.status(400).json({ success: false, message: 'Missing sender ID or receiver email' });
    }
    try {
        const sender = await Sender.findOne({ uniqueId: senderId });
        if (!sender) { return res.status(404).json({ success: false, message: 'Sender not found' }); }

        const receiverIndex = sender.receivers.findIndex(r => r.email === receiverEmail);
        if (receiverIndex === -1) { return res.status(404).json({ success: false, message: 'Receiver not found' }); }

        if (sender.receivers[receiverIndex].fileRequest?.status === 'pending') {
            sender.receivers[receiverIndex].fileRequest = { status: 'idle' }; 
            await sender.save();
            res.json({ success: true, message: 'Request cancelled successfully', status: 'idle' });
i     } else {
            res.status(400).json({ success: false, message: 'No pending request found to cancel', status: sender.receivers[receiverIndex].fileRequest?.status || 'idle' });
        }
    } catch (error) {
        console.error("Error cancelling request:", error);
        res.status(500).json({ success: false, message: 'Server error cancelling request' });
    }
});


// --- Sender approves request ---
app.post('/approve-request', async (req, res) => {
    const { senderId, receiverEmail, fileUrl, originalFileName } = req.body;
     if (!senderId || !receiverEmail || !fileUrl || !originalFileName) {
        return res.status(400).json({ success: false, message: 'Missing required approval data (senderId, receiverEmail, fileUrl, originalFileName)' });
    }
     try {
        const sender = await Sender.findOne({ uniqueId: senderId });
        if (!sender) { return res.status(404).json({ success: false, message: 'Sender not found' }); }

        const receiverIndex = sender.receivers.findIndex(r => r.email === receiverEmail);
        if (receiverIndex === -1) { return res.status(404).json({ success: false, message: 'Receiver not found' }); }

        sender.receivers[receiverIndex].fileRequest = {
            status: 'approved',
            requestedAt: sender.receivers[receiverIndex].fileRequest?.requestedAt, 
            approvedFileUrl: fileUrl,
            approvedFileName: originalFileName,
            approvedAt: new Date()
        };

        await sender.save();
        res.json({ success: true, message: 'Request approved successfully', status: 'approved' });
    } catch (error) {
        console.error("Error approving request:", error);
        res.status(500).json({ success: false, message: 'Server error approving request' });
    }
});

// --- Sender denies request ---
app.post('/deny-request', async (req, res) => {
    const { senderId, receiverEmail } = req.body;
    if (!senderId || !receiverEmail) {
        return res.status(400).json({ success: false, message: 'Missing sender ID or receiver email' });
    }
    try {
        const sender = await Sender.findOne({ uniqueId: senderId });
        if (!sender) { return res.status(404).json({ success: false, message: 'Sender not found' }); }

        const receiverIndex = sender.receivers.findIndex(r => r.email === receiverEmail);
        if (receiverIndex === -1) { return res.status(404).json({ success: false, message: 'Receiver not found' }); }

        sender.receivers[receiverIndex].fileRequest = {
             status: 'denied',
             requestedAt: sender.receivers[receiverIndex].fileRequest?.requestedAt 
        };

        await sender.save();
        res.json({ success: true, message: 'Request denied successfully', status: 'denied' });
    } catch (error) {
         console.error("Error denying request:", error);
        res.status(500).json({ success: false, message: 'Server error denying request' });
s   }
});

// --- Sender gets pending requests ---
app.get('/sender-requests/:senderId/pending', async (req, res) => {
    const { senderId } = req.params;
    if (!senderId) {
        return res.status(400).json({ success: false, message: 'Missing sender ID' });
    }
    try {
        const sender = await Sender.findOne({ uniqueId: senderId });
        if (!sender) {
            return res.status(404).json({ success: false, message: 'Sender not found' });
        }

        const pendingRequests = [];
        sender.receivers.forEach(receiver => {
            if (receiver.fileRequest && receiver.fileRequest.status === 'pending') {
                pendingRequests.push({
                    receiverEmail: receiver.email, 
                    requestedAt: receiver.fileRequest.requestedAt,
                });
            }
        });

        pendingRequests.sort((a, b) => new Date(b.requestedAt || 0) - new Date(a.requestedAt || 0));
        res.json({ success: true, requests: pendingRequests });

    } catch (error) {
        console.error("Error fetching pending requests:", error);
        res.status(500).json({ success: false, message: 'Server error fetching pending requests' });
    }
});

// --- Mark file as downloaded (clear approved request) ---
app.post('/mark-downloaded', async (req, res) => {
    const { senderId, receiverEmail } = req.body;
    if (!senderId || !receiverEmail) {
        return res.status(400).json({ success: false, message: 'Missing sender ID or receiver email' });
    }
    try {
        const sender = await Sender.findOne({ uniqueId: senderId });
        if (!sender) {
            return res.status(404).json({ success: false, message: 'Sender not found' });
        }
        const receiverIndex = sender.receivers.findIndex(r => r.email === receiverEmail);
        if (receiverIndex === -1) {
            return res.status(404).json({ success: false, message: 'Receiver not found' });
        }
        sender.receivers[receiverIndex].fileRequest = { status: 'idle' };
        await sender.save();
        res.json({ success: true, message: 'File marked as downloaded and request cleared.' });
A   } catch (error) {
        console.error("Error marking file as downloaded:", error);
        res.status(500).json({ success: false, message: 'Server error clearing request' });
    }
});

// --- Start server ---
// --- Start server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
