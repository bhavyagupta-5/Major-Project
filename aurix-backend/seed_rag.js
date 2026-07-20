const fs = require('fs');
const path = require('path');
const { supabaseAdmin } = require('./supabaseClient');

let pipeline;

async function initTransformers() {
    const transformers = await import('@xenova/transformers');
    pipeline = transformers.pipeline;
}

const rawDocs = [
    {
        title: "SQL Injection Mitigation",
        content: "Use parameterized queries or prepared statements. Do not concatenate strings into SQL queries."
    },
    {
        title: "Insecure Deserialization (Pickle)",
        content: "Avoid using pickle with untrusted data. Use JSON or safer formats instead. Python's pickle module can execute arbitrary code upon unpickling."
    },
    {
        title: "Cross-Site Scripting (XSS)",
        content: "Sanitize and escape all user input before rendering it in the browser. Use context-aware output encoding."
    }
];

async function seedDatabase() {
    await initTransformers();

    console.log("Loading embedding model (all-MiniLM-L6-v2)...");
    const generateEmbedding = await pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2');

    console.log("Processing documents...");
    for (const doc of rawDocs) {
        const output = await generateEmbedding(doc.content, { pooling: 'mean', normalize: true });
        const embedding = Array.from(output.data);

        const { error } = await supabaseAdmin
            .from('threat_intelligence')
            .insert([{
                title: doc.title,
                content: doc.content,
                metadata: { source: 'OWASP' },
                embedding: embedding
            }]);

        if (error) {
            console.error(`Failed to insert document: ${doc.title}`, error);
        } else {
            console.log(`Successfully seeded document: ${doc.title}`);
        }
    }

    console.log("Seeding complete!");
    process.exit(0);
}

seedDatabase();
