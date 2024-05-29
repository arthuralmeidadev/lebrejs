import net from "net";
import crypto from "crypto";

/**
 * @public
 */
export class Lebre {
  /**
   * @private @type net.Socket
   */
  socket = new net.Socket();
  /**
   * @private @type string
   */
  publicKey = undefined;
  /**
   * @private @type string
   */
  privateKey = undefined;
  /**
   * @private @type boolean
   */
  authenticated = false;
  /**
   * @private @type Buffer
   */
  buffer = Buffer.alloc(0);;
  /**
   * @private @type boolean
   */
  isExpectingKey = false;
  /**
    * @private @type Array<{
    *   resolve: (value: string | PromiseLike<string>);
    *   reject: (reason?: any) => void;
    * }>
    */
  pendingRequestsQueue = [];
  options = {
    host: "127.0.0.1",
    port: 5051,
  }

  user = undefined;
  password = undefined;

  /**
   * @public
   */
  constructor(options) {
    this.user = options.user;
    this.password = options.password;
    this.options.host = options.host ?? this.options.host;
    this.options.port = options.port ?? this.options.port;
  }

  /**
   * @public @returns {Promise<void>}
   */
  async connect(callback, connOptions) {
    return new Promise((resolve, reject) => {
      try {
        const {
          publicKey: serverPublicKey,
          privateKey: clientPrivateKey,
        } = crypto.generateKeyPairSync("rsa", {
          modulusLength: 2048,
          publicKeyEncoding: {
            type: "spki",
            format: "pem"
          },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
          },
        });

        this.privateKey = clientPrivateKey;
        if (connOptions) {

          this.socket.connect(connOptions.port ?? this.options.port, connOptions.host ?? this.options.host);
        } else {
          this.socket.connect(this.options.port, this.options.host);
        }

        this.socket.on("connect", () => {
          console.log("Connected to server");
          this.socket.write(serverPublicKey);
          if (callback) {
            callback();
          }
        });

        this.socket.on("data", (data) => this.handleResponse(data, resolve));
        this.socket.on("close", () => {
          console.log("Connection closed");
        });
      } catch (error) {
        return reject(error);
      }
    })
  }

  /**
   * @public @returns {Promise<void>}
   * @param {string} key 
   * @param {string} value 
   */
  async set(key, value) {
    if (this.privateKey && this.authenticated) {
      try {
        const keyType = typeof key;
        const valueType = typeof value;

        if (valueType !== "string") {
          throw new TypeError("Invalid type for parameter 'value'.\nExpected string, got " + valueType);
        } else if (keyType !== "string") {
          throw new TypeError("Invalid type for parameter 'key'.\nExpected string, got " + keyType);
        }

        this.sendMessage(`V1.0 SET ${key} ${value.replace(/ /g, "\\u0020")}`);

        return new Promise((resolve, reject) => {
          this.pendingRequestsQueue.push({ resolve, reject });
        });
      } catch (error) {
        throw error;
      }
    }
  }

  /**
   * @public @returns {Promise<string>}
   * @param {string} value 
   */
  async get(key) {
    if (this.publicKey && this.authenticated) {
      try {
        const keyType = typeof key;
        if (keyType !== "string") {
          throw new TypeError("Invalid type for parameter 'key'.\nExpected string, got " + keyType);
        }

        this.sendMessage(`V1.0 GET ${key}`);
        return new Promise((resolve, reject) => {
          const message = new Promise((resolve, reject) => {
            this.pendingRequestsQueue.push({ resolve, reject });
          }).then((value) => {
            if (value.startsWith("VALUE")) {
              return value.slice(6);
            }

            throw new Error(`Couldn't GET ${key}: ${value}`);
          }).catch((error) => {
            throw error;
          });

          if (message) {
            return resolve(message);
          }

          reject(new Error("Message not found"));
        });
      } catch (error) {
        throw error;
      }
    }
  }

  /**
   * @public @returns {Promise<void>}
   * @param {string} value 
   */
  async delete(key) {
    if (this.privateKey && this.authenticated) {
      try {
        const keyType = typeof key;
        if (keyType !== "string") {
          throw new TypeError("Invalid type for parameter 'key'.\nExpected string, got " + keyType);
        }

        this.sendMessage(`V1.0 DELETE ${key}`);

        return new Promise((resolve, reject) => {
          const message = new Promise((resolve, reject) => {
            this.pendingRequestsQueue.push({ resolve, reject });
          }).then((value) => {
            if (value.startsWith("OK")) {
              return value;
            }

            throw new Error(`Couldn't SET ${key}: \n${value}`);
          }).catch((error) => {
            throw error;
          });

          if (message) {
            return resolve();
          }

          reject(new Error("Message not found"));
        });
      } catch (error) {
        throw error;
      }
    }
  }

  /**
   * @public @returns {Promise<void>}
   */
  async disconnect(callback) {
    this.socket.end();
    if (callback) {
      callback();
    }
  }

  /**
   * @private @returns {void}
   * @param {Buffer} data
   * @param {(value: void | PromiseLike<void>) => void} resolveStart
   */
  handleResponse(data, resolveStart) {
    this.buffer = Buffer.concat([this.buffer, data]);

    // Read while the first 4 bytes convey message length
    while (this.buffer.length >= 4) {
      const message = this.extractMessageFromBuffer();

      if (message === "SERVER RECEIVED KEY") {
        this.isExpectingKey = true;
        continue;
      }

      if (!this.publicKey && this.isExpectingKey) {
        this.publicKey = crypto.createPublicKey(message);
        this.isExpectingKey = false;

        if (!this.authenticated) {
          this.sendMessage(`V1.0 AUTH ${this.user} ${this.password}`)
          this.authenticated = true;
        }

        resolveStart();
        continue;
      }

      const { resolve, reject } = this.pendingRequestsQueue.shift();
      if (resolve) {
        return resolve(message);
      }

      reject(new Error("No pending request to match response"));
    }
  }

  /**
   * @private @returns {string}
   */
  extractMessageFromBuffer() {
    // read the first 32 bits (index 0) in Big Endian order
    // containing the message length integer
    const messageLength = this.buffer.readInt32BE(0)

    if (this.buffer.length < messageLength + 4) {
      return;
    }

    const message = this.buffer.subarray(4, messageLength + 4);
    this.buffer = this.buffer.subarray(messageLength + 4);

    if (!this.publicKey) {
      return message.toString();
    }

    return crypto.privateDecrypt(
      {
        key: this.privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      message,
    ).toString();
  }

  /**
   * @private @returns {void}
   * @param {string} message 
   */
  sendMessage(message) {
    const encryptedMessage = crypto.publicEncrypt(
      {
        key: this.publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      Buffer.from(message),
    );

    const messageLength = Buffer.alloc(4);
    messageLength.writeUInt32BE(encryptedMessage.length, 0);

    // Prepend message length information to
    // first 32 bits in Big Endian order
    const finalData = Buffer.concat([messageLength, encryptedMessage])
    this.socket.write(finalData);
  }
}