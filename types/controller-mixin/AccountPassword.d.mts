import { ControllerMixin } from '@lionrockjs/mvc';
export default class ControllerMixinAccountPassword extends ControllerMixin {
    static USER: string;
    static DATABASE_NAME: any;
    static IDENTIFIER_DATABASE_NAME: any;
    static IDENTIFIER: string;
    static init(state: Map<string, any>): void;
    static action_change_password_post(state: Map<string, any>): Promise<void>;
    static action_change_password_done(state: Map<string, any>): Promise<void>;
}
