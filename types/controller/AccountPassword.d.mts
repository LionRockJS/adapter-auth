import { ControllerAccount } from '@lionrockjs/mod-auth';
export default class ControllerAccountPassword extends ControllerAccount {
    static mixins: any[];
    constructor(request: any);
    action_index(): Promise<void>;
    action_change_password_post(): Promise<void>;
    action_change_password_done(): Promise<void>;
}
