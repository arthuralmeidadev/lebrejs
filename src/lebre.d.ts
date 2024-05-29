declare module "lebre" {
    export type ConnectionOptions = {
        host?: string;
        port?: number;
    }

    export class Lebre {
        public options: ConnectionOptions;

        /**
         * If not passed in the `options` object, `host` defaults to *127.0.0.1* and `port` defaults to *5051*
         * @since v1.0.0
        */
        public constructor(options: {
            user: string;
            password: string;
        } & ConnectionOptions);

        /**
         * Pass `host` or `port` in the `connOptions` object to override the values set during class instantiation
         * @since v1.0.0
        */
        public async connect(callback?: (() => void) | null, connOptions?: ConnectionOptions): Promise<void>;

        public async set(key: string, value: string): Promise<void>;

        public async get(key: string): Promise<string>;

        public async delete(key: string): Promise<void>;

        public async disconnect(callback?: () => void): Promise<void>;
    }
}
