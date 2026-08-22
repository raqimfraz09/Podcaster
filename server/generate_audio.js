const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
require('dotenv').config();

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Function to generate a real, high quality playable WAV audio file (e.g. ambient podcast intro music)
function generateWavAudio(filename, durationSeconds = 30, baseFreq = 220, chordType = 'ambient') {
    const sampleRate = 44100;
    const numChannels = 2;
    const bytesPerSample = 2; // 16-bit
    const blockAlign = numChannels * bytesPerSample;
    const byteRate = sampleRate * blockAlign;
    const totalSamples = sampleRate * durationSeconds;
    const dataSize = totalSamples * blockAlign;

    const buffer = Buffer.alloc(44 + dataSize);

    // RIFF header
    buffer.write('RIFF', 0);
    buffer.writeUInt32LE(36 + dataSize, 4);
    buffer.write('WAVE', 8);

    // fmt subchunk
    buffer.write('fmt ', 12);
    buffer.writeUInt32LE(16, 16); // Subchunk1Size (16 for PCM)
    buffer.writeUInt16LE(1, 20);  // AudioFormat (1 = PCM)
    buffer.writeUInt16LE(numChannels, 22);
    buffer.writeUInt32LE(sampleRate, 24);
    buffer.writeUInt32LE(byteRate, 28);
    buffer.writeUInt16LE(blockAlign, 32);
    buffer.writeUInt16LE(bytesPerSample * 8, 34); // BitsPerSample

    // data subchunk
    buffer.write('data', 36);
    buffer.writeUInt32LE(dataSize, 40);

    let offset = 44;
    for (let i = 0; i < totalSamples; i++) {
        const t = i / sampleRate;

        // Create warm ambient chord with gentle envelope
        const env = Math.sin((Math.PI * i) / totalSamples); // smooth in and out
        const beat = 0.8 + 0.2 * Math.sin(2 * Math.PI * 2 * t);

        let leftSample = 0;
        let rightSample = 0;

        if (chordType === 'ambient') {
            // C Major 7th / F Major warm pad
            leftSample = 0.3 * Math.sin(2 * Math.PI * baseFreq * t)
                       + 0.2 * Math.sin(2 * Math.PI * (baseFreq * 1.25) * t)
                       + 0.15 * Math.sin(2 * Math.PI * (baseFreq * 1.5) * t);
            rightSample = 0.3 * Math.sin(2 * Math.PI * (baseFreq * 1.005) * t)
                        + 0.2 * Math.sin(2 * Math.PI * (baseFreq * 1.5) * t)
                        + 0.15 * Math.sin(2 * Math.PI * (baseFreq * 1.875) * t);
        } else if (chordType === 'tech') {
            // Tech synth arpeggio pulse
            const arpFreq = baseFreq * (1 + (Math.floor(t * 4) % 4) * 0.25);
            leftSample = 0.35 * Math.sin(2 * Math.PI * arpFreq * t);
            rightSample = 0.35 * Math.sin(2 * Math.PI * (arpFreq * 1.5) * t);
        } else if (chordType === 'chill') {
            // Lo-fi warm chords
            leftSample = 0.3 * Math.sin(2 * Math.PI * baseFreq * t) + 0.2 * Math.sin(2 * Math.PI * (baseFreq * 1.33) * t);
            rightSample = 0.3 * Math.sin(2 * Math.PI * (baseFreq * 1.5) * t) + 0.2 * Math.sin(2 * Math.PI * (baseFreq * 1.77) * t);
        } else {
            // Acoustic bell tone
            leftSample = 0.35 * Math.sin(2 * Math.PI * baseFreq * t) * Math.exp(-t % 2);
            rightSample = 0.35 * Math.sin(2 * Math.PI * (baseFreq * 1.25) * t) * Math.exp(-t % 2);
        }

        const lVal = Math.max(-1, Math.min(1, leftSample * env * beat));
        const rVal = Math.max(-1, Math.min(1, rightSample * env * beat));

        buffer.writeInt16LE(Math.floor(lVal * 32767), offset);
        buffer.writeInt16LE(Math.floor(rVal * 32767), offset + 2);
        offset += 4;
    }

    const filePath = path.join(uploadsDir, filename);
    fs.writeFileSync(filePath, buffer);
    console.log(`Generated audio: ${filename} (${(buffer.length / 1024 / 1024).toFixed(2)} MB, ${durationSeconds}s)`);
}

// Generate the 4 demo audio files
generateWavAudio('sample-track-1.mp3', 45, 220, 'tech');     // Tech & AI intro
generateWavAudio('sample-track-2.mp3', 60, 261.63, 'ambient'); // Business & SaaS
generateWavAudio('sample-track-3.mp3', 40, 329.63, 'chill');   // Comedy & Talk
generateWavAudio('sample-track-4.mp3', 50, 196.00, 'bell');    // Health & Focus

console.log("All audio tracks generated successfully!");
