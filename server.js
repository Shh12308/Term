const WebSocket = require('ws');
const { spawn } = require('child_process');

// Configure WebSocket server
const wss = new WebSocket.Server({ port: 8080 });

// List of allowed commands to prevent shell injection
const allowedCommands = ['ls', 'pwd', 'echo', 'cat', 'uptime', 'whoami', 'date'];

wss.on('connection', (ws) => {
    ws.send('Welcome to the secure Linux terminal! Type a command to begin...');

    ws.on('message', (message) => {
        console.log(`Received: ${message}`);

        // Sanitize input: check if the command is allowed
        const commandArgs = message.split(' ');
        const command = commandArgs[0];

        if (allowedCommands.includes(command)) {
            // Execute command safely
            executeCommand(command, commandArgs.slice(1), ws);
        } else {
            // Return error for unallowed commands
            ws.send('Error: Command not allowed.');
        }
    });

    // Timeout for execution (optional)
    const timeout = setTimeout(() => {
        ws.send('Error: Command execution timed out.');
    }, 5000); // 5 seconds timeout

    // Clean up timeout on completion
    function executeCommand(command, args, ws) {
        const cmdProcess = spawn(command, args);

        let output = '';
        cmdProcess.stdout.on('data', (data) => {
            output += data;
        });

        cmdProcess.stderr.on('data', (data) => {
            output += `stderr: ${data}`;
        });

        cmdProcess.on('close', (code) => {
            clearTimeout(timeout); // Clear the timeout
            if (code !== 0) {
                ws.send(`Error: Command execution failed with code ${code}`);
            } else {
                ws.send(output);
            }
        });
    }
});

console.log('WebSocket server is listening on ws://localhost:8080');
