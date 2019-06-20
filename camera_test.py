    def check_fps(self, codec="h264", fps=0, **kwargs):
        fps_list = {"30":2, "15":1, "10":0}
        self.dut.set_param("RtspServer.Enabled", 1)
        self.dut.set_param("RtspServer.AnonymousAccess", 1)
        self.dut.set_param("RtspServer.Video.{}.Resolution".format(codec), 0)
        self.dut.set_param("RtspServer.Video.{}.Framerate".format(codec), fps_list[fps])
        time.sleep(5)

        t = 10
        p = subprocess.Popen("ffmpeg -i rtsp://{}/{}_stream -t {} -vcodec copy -f avi -y {}/video.avi".format(self.dut.address, codec, t, self.temp_path).split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout_data, stderr_data = p.communicate(timeout=(t+15))
            logging.info(stdout_data.decode("utf-8"))
            logging.info(stderr_data.decode("utf-8"))
        except subprocess.TimeoutExpired:
            p.terminate()
            # zde by měl test selhat
                
        frame_rate = round(int(re.findall('\d+', subprocess.check_output("ffprobe -select_streams v -count_frames -show_entries stream=nb_read_frames {}/video.avi".format(self.temp_path).split(), timeout=5, stderr=subprocess.PIPE).decode("utf-8"))[0]) / t)
                
        tol = 0.15
        min_val = (int(fps) - round(int(fps)*tol))
        max_val = (int(fps) + round(int(fps)*tol))

        self.fail("shouldn't happen")
        
