void check_call_ret(const char *umsg, int objerrno, int ret, bool fatal) {
        char errbuf[STRERRLEN];
        int my_ret = 0;

        internal_log(NULL, DEBUG_LEVEL, "checking errno %d message of [%s], return value: %d fatal %d", objerrno, umsg, ret, fatal);

        if(ret != -1)
                return;

        if(objerrno)
                snprintf(errbuf, STRERRLEN, "%s: %s", umsg, strerror(objerrno));
        else
                snprintf(errbuf, STRERRLEN, "%s ", umsg);

        if(fatal) {
                internal_log(NULL, ALL_LEVEL, "fatal error: %s", errbuf);
                SjProc->CleanExit(true);
        } else {
                internal_log(NULL, ALL_LEVEL, "error: %s", errbuf);
        }
}

/* forceflow is almost useless, use NULL in the normal logging options */
void internal_log(FILE *forceflow, int errorlevel, const char *msg, ...) {
        va_list arguments;
        time_t now = time(NULL);
        FILE *output_flow;

        if(forceflow == NULL && useropt.logstream == NULL)
                return;

        if(forceflow != NULL)
                output_flow = forceflow;
        else
                output_flow = useropt.logstream;

        if(errorlevel == PACKETS_DEBUG && useropt.packet_logstream != NULL)
                output_flow = useropt.packet_logstream;

        if(errorlevel == HACKS_DEBUG && useropt.hacks_logstream != NULL)
                output_flow = useropt.hacks_logstream;

        if(errorlevel <= useropt.debug_level) {
                char *time = strdup(asctime(localtime(&now)));

                va_start(arguments, msg);
                time[strlen(time) -1] = ' ';
                fprintf(output_flow, "%s ", time);
                vfprintf(output_flow, msg, arguments);
                fprintf(output_flow, "\n");
                fflush(output_flow);
                va_end(arguments);
                free(time);
        }
}
