import {defineStore} from "pinia";

export const localStore = defineStore('local', {
    state: () => ({
        darkTheme: true,
        layout: 'simple',
        isCollapsed: true,
        menuKey: '',
        auth: {
            token: '',
            expAt: ''
        },
    }),
    getters: {},
    actions: {
        setLayout(name) {
            this.layout = name
        }
    },
    persist: true
})