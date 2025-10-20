// models/Sender.js
const mongoose = require('mongoose');

// File Request Sub-Schema
const FileRequestSchema = new mongoose.Schema({
    status: {
        type: String,
        enum: ['idle', 'pending', 'approved', 'denied'], // Possible states
        default: 'idle'
    },
    requestedAt: { type: Date },        // When the request was made
    approvedFileUrl: { type: String },  // S3 URL provided upon approval
    approvedFileName: { type: String }, // Original filename provided upon approval
    approvedAt: { type: Date }          // When the request was approved
    // We don't need a separate requestId here unless multiple simultaneous requests are needed
}, { _id: false }); // Don't create a separate _id for this sub-document

// Receiver Schema (Updated)
const ReceiverSchema = new mongoose.Schema({
  email: { type: String, required: true },
  password: { type: String, required: true },
  keys: [
    {
      image: { type: String, required: true },          // Original image name
      encryptedImage: { type: String, required: true }, // Encrypted filename
      key: { type: String, required: true },            // Encryption key (Consider if still needed)
      hash: { type: String },                           // Combined seeds/hashes string
      code_sent: { type: String },                      // 5-digit code sent to receiver
      createdAt: { type: Date, default: Date.now }
    }
  ],
  // --- ADDED File Request Tracking ---
  fileRequest: {
      type: FileRequestSchema,
      default: () => ({ status: 'idle' }) // Ensure default status is 'idle'
  },
  // --- END ADDED ---
  createdAt: { type: Date, default: Date.now }
});

// Sender Schema (remains the same structure)
const SenderSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  uniqueId: { type: String, required: true, unique: true },
  receivers: [ReceiverSchema] // Embeds the updated ReceiverSchema
}, { timestamps: true });

module.exports = mongoose.model('Sender', SenderSchema);