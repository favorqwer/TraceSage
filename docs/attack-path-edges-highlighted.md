# 六个模拟攻击在 backtrack.dot / final.dot 中的细节事件边整理
入口节点

`2552: 192.168.122.129:35082->192.168.122.128:8000`

`905: 192.168.122.129:54720->192.168.122.128:80`

`18031: 192.168.122.128:46984->192.168.122.129:22`

`4229: 192.168.122.128:47550->192.168.122.129:22`

`1190: 192.168.122.129:50584->192.168.122.128:8084`

`1447: 192.168.122.129:33492->192.168.122.128:8085`

这里的计算口径是：
- final图边数：final.dot中边按实际出现次数统计，重复边重复计数
- GT边数：按此文档原始条目统计
- FP：final.dot中出现但不在 GT 里的边都计入，即噪音边（包含重复边FP=final图边数-GT边数+FN）
- FN：GT 中存在、但final.dot一次都没出现过的边数，即边和边
- Precision = (GT边数 - FN) / final图边数
- Recall = (GT边数 - FN) / GT边数



## 1. Multi Stage Data Exfiltration

2552: 192.168.122.129:35082->192.168.122.128:8000 --recvfrom--> 2544: /usr/bin/wget
2544: /usr/bin/wget --write--> 2550: /tmp/update_patch.sh
2544: /usr/bin/wget --execve--> 526: /bin/bash
526: /bin/bash --execve--> 2586: /usr/bin/mv
526: /bin/bash --execve--> 2594: /usr/bin/chmod
526: /bin/bash --execve--> 2610: /tmp/.system_service.sh
2595: /tmp/.system_service.sh --read--> 2610: /tmp/.system_service.sh
2610: /tmp/.system_service.sh --execve--> 2613: /usr/bin/mkdir
2610: /tmp/.system_service.sh --execve--> 2616: /usr/bin/cp
371: /etc/passwd --read--> 2616: /usr/bin/cp
2616: /usr/bin/cp --write--> 2617: /tmp/.hidden_dir/target_data.txt
2610: /tmp/.system_service.sh --execve--> 2620: /usr/bin/tar
2617: /tmp/.hidden_dir/target_data.txt --read--> 2620: /usr/bin/tar
2620: /usr/bin/tar --execve--> 2624: /bin/sh
2624: /bin/sh --execve--> 2627: /usr/bin/gzip
2627: /usr/bin/gzip --write--> 2622: /tmp/stolen_data.tar.gz
2610: /tmp/.system_service.sh --execve--> 2631: /usr/bin/cat
2622: /tmp/stolen_data.tar.gz --read--> 2631: /usr/bin/cat
2610: /tmp/.system_service.sh --execve--> 2633: /usr/bin/nc
2633: /usr/bin/nc --write--> 2635: 192.168.122.129:49580->192.168.122.128:4444



## 2. Masquerade Data Exfiltration

905: 192.168.122.129:54720->192.168.122.128:80 --recvfrom--> 888: /usr/bin/wget
888: /usr/bin/wget --write--> 901: /tmp/update_patch.sh
881: /usr/bin/bash --execve--> 913: /usr/bin/chmod
881: /usr/bin/bash --execve--> 959: /tmp/update_patch.sh
959: /tmp/update_patch.sh --execve--> 966: /usr/bin/cp
966: /usr/bin/cp --write--> 971: /tmp/.sys_kernel_check_v2
959: /tmp/update_patch.sh --execve--> 974: /usr/bin/chmod
959: /tmp/update_patch.sh --execve--> 977: /usr/bin/sleep
959: /tmp/update_patch.sh --execve--> 4266: /usr/bin/curl
2803: /etc/passwd --read--> 4266: /usr/bin/curl
4266: /usr/bin/curl --sendto--> 4292: 192.168.122.129:47160->192.168.122.128:4444



## 3. SSH Spray

18031: 192.168.122.128:46984->192.168.122.129:22 --read--> 18202: /usr/sbin/sshd
18202: /usr/sbin/sshd --execve--> 18219: /bin/bash
18219: /bin/bash --execve--> 18221: /usr/bin/mkdir
18219: /bin/bash --execve--> 18228: /usr/bin/date
18219: /bin/bash --execve--> 18230: /usr/bin/whoami
18219: /bin/bash --execve--> 18239: /usr/bin/id
18219: /bin/bash --execve--> 18243: /usr/bin/uname
18219: /bin/bash --execve--> 18253: /usr/bin/head
18219: /bin/bash --execve--> 18255: /usr/bin/stat
18228: /usr/bin/date --write--> 18226: /home/labssh/progql_lab_notes/session_30/enumeration.txt
18230: /usr/bin/whoami --write--> 18226: /home/labssh/progql_lab_notes/session_30/enumeration.txt
18239: /usr/bin/id --write--> 18226: /home/labssh/progql_lab_notes/session_30/enumeration.txt
18243: /usr/bin/uname --write--> 18226: /home/labssh/progql_lab_notes/session_30/enumeration.txt
18253: /usr/bin/head --write--> 18226: /home/labssh/progql_lab_notes/session_30/enumeration.txt
18255: /usr/bin/stat --write--> 18226: /home/labssh/progql_lab_notes/session_30/enumeration.txt
18219: /bin/bash --write--> 18226: /home/labssh/progql_lab_notes/session_30/enumeration.txt



## 4. Site Defacement

4229: 192.168.122.128:47550->192.168.122.129:22 --read--> 5166: /usr/sbin/sshd
5166: /usr/sbin/sshd --execve--> 5364: /usr/lib/openssh/sftp-server
5364: /usr/lib/openssh/sftp-server --write--> 5367: /home/labweb/incoming/deface_release.tar.gz
5364: /usr/lib/openssh/sftp-server --write--> 5377: /home/labweb/incoming/deface_release.sha256
7388: 192.168.122.128:48008->192.168.122.129:22 --read--> 7559: /usr/sbin/sshd
7559: /usr/sbin/sshd --execve--> 7569: /bin/bash
5377: /home/labweb/incoming/deface_release.sha256 --read--> 7047: /usr/bin/sha256sum
7569: /bin/bash --execve--> 7571: /usr/bin/date
7569: /bin/bash --execve--> 7573: /usr/bin/mkdir
7569: /bin/bash --execve--> 7576: /usr/bin/tar
129: /srv/progql-web/current/release.txt --read--> 7576: /usr/bin/tar
127: /srv/progql-web/current/assets/site.css --read--> 7576: /usr/bin/tar
118: /srv/progql-web/current/index.html --read--> 7576: /usr/bin/tar
7569: /bin/bash --execve--> 7586: /usr/bin/cp
127: /srv/progql-web/current/assets/site.css --read--> 7586: /usr/bin/cp
118: /srv/progql-web/current/index.html --read--> 7586: /usr/bin/cp
129: /srv/progql-web/current/release.txt --read--> 7586: /usr/bin/cp
7569: /bin/bash --execve--> 7591: /usr/bin/tar
5367: /home/labweb/incoming/deface_release.tar.gz --read--> 7596: /usr/bin/gzip
7591: /usr/bin/tar --execve--> 7596: /usr/bin/gzip
7591: /usr/bin/tar --write--> 7598: /srv/progql-web/releases/release_20260531-211727/index.html
7591: /usr/bin/tar --write--> 7597: /srv/progql-web/releases/release_20260531-211727/release.txt
7591: /usr/bin/tar --write--> 7599: /srv/progql-web/releases/release_20260531-211727/notice.txt
7591: /usr/bin/tar --write--> 7600: /srv/progql-web/releases/release_20260531-211727/assets/site.css
7569: /bin/bash --execve--> 7604: /usr/bin/cp
7598: /srv/progql-web/releases/release_20260531-211727/index.html --read--> 7604: /usr/bin/cp
7569: /bin/bash --execve--> 7606: /usr/bin/cp
7597: /srv/progql-web/releases/release_20260531-211727/release.txt --read--> 7606: /usr/bin/cp
7569: /bin/bash --execve--> 7611: /usr/bin/cp
7599: /srv/progql-web/releases/release_20260531-211727/notice.txt --read--> 7611: /usr/bin/cp
7569: /bin/bash --execve--> 7615: /usr/bin/mkdir
7569: /bin/bash --execve--> 7617: /usr/bin/cp
7600: /srv/progql-web/releases/release_20260531-211727/assets/site.css --read--> 7617: /usr/bin/cp
7569: /bin/bash --execve--> 7621: /usr/bin/date
7569: /bin/bash --write--> 7627: /srv/progql-web/deploy.log
7569: /bin/bash --execve--> 7629: /usr/bin/sha256sum
5367: /home/labweb/incoming/deface_release.tar.gz --read--> 7629: /usr/bin/sha256sum
7569: /bin/bash --write--> 7632: /srv/progql-web/current/COMPROMISED_MARKER.txt



## 5. User Timer Resource Hijack

1172: /usr/bin/curl --sendto--> 1190: 192.168.122.129:50584->192.168.122.128:8084
1190: 192.168.122.129:50584->192.168.122.128:8084 --recvfrom--> 1172: /usr/bin/curl
1172: /usr/bin/curl --write--> 1191: /tmp/diag_update_bundle.tar.gz
1191: /tmp/diag_update_bundle.tar.gz --read--> 1200: /usr/bin/gzip
1200: /usr/bin/gzip --execve--> 1194: /usr/bin/tar
1194: /usr/bin/tar --write--> 1201: /tmp/diag_update/worker.sh
1194: /usr/bin/tar --write--> 1202: /tmp/diag_update/install.sh
1194: /usr/bin/tar --write--> 1203: /tmp/diag_update/burst_profile.txt
1202: /tmp/diag_update/install.sh --read--> 1212: /usr/bin/bash
1212: /usr/bin/bash --execve --> 1220: /usr/bin/mkdir
1212: /usr/bin/bash --execve --> 1229: /usr/bin/cp
1212: /usr/bin/bash --execve --> 1233: /usr/bin/cp
1201: /tmp/diag_update/worker.sh --read--> 1229: /usr/bin/cp
1203: /tmp/diag_update/burst_profile.txt --read--> 1233: /usr/bin/cp
1229: /usr/bin/cp --write--> 1231: /home/ubuntu/.local/share/progql-helper/worker.sh
1233: /usr/bin/cp --write--> 1234: /home/ubuntu/.local/share/progql-helper/burst_profile.txt
1212: /usr/bin/bash --execve --> 1237: /usr/bin/chmod
1237: /usr/bin/chmod --chmod--> 1231: /home/ubuntu/.local/share/progql-helper/worker.sh
1212: /usr/bin/bash --execve --> 1241: /usr/bin/cat
1212: /usr/bin/bash --execve --> 1244: /usr/bin/cat
1241: /usr/bin/cat --write--> 1239: /home/ubuntu/.config/systemd/user/progql-helper.service
1244: /usr/bin/cat --write--> 1243: /home/ubuntu/.config/systemd/user/progql-helper.timer
1239: /home/ubuntu/.config/systemd/user/progql-helper.service --read--> 1252: /usr/lib/systemd/systemd
1243: /home/ubuntu/.config/systemd/user/progql-helper.timer --read--> 1252: /usr/lib/systemd/systemd
1252: /usr/lib/systemd/systemd --execve--> 8733: /home/ubuntu/.local/share/progql-helper/worker.sh
1252: /usr/lib/systemd/systemd --execve--> 8734: /usr/bin/bash
1252: /usr/lib/systemd/systemd --write--> 2490: /sys/fs/cgroup/user.slice/user-1000.slice/user1000.service/app.slice/progql-helper.service/cgroup.procs
2490: /sys/fs/cgroup/user.slice/user-1000.slice/user1000.service/app.slice/progql-helper.service/cgroup.procs --read--> 1252: /usr/lib/systemd/systemd
1231: /home/ubuntu/.local/share/progql-helper/worker.sh --read--> 8734: /usr/bin/bash
8734: /usr/bin/bash --execve--> 8736: /usr/bin/mkdir
8734: /usr/bin/bash --execve--> 8738: /usr/bin/date
8734: /usr/bin/bash --execve--> 8740: /usr/bin/mkdir
8734: /usr/bin/bash --execve--> 8742: /usr/bin/cp
1234: /home/ubuntu/.local/share/progql-helper/burst_profile.txt --read--> 8742: /usr/bin/cp
8742: /usr/bin/cp --write--> 8743: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/local_profile_copy.txt
8734: /usr/bin/bash --execve--> 8745: /usr/bin/curl
8745: /usr/bin/curl --sendto--> 8746: 192.168.122.129:49186->192.168.122.128:8084
8746: 192.168.122.129:49186->192.168.122.128:8084 --recvfrom--> 8745: /usr/bin/curl
8745: /usr/bin/curl --write--> 8747: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/remote_profile_copy.txt
8734: /usr/bin/bash --execve--> 8749: /usr/bin/cp
8749: /usr/bin/cp --write--> 8750: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/cpuinfo.txt
8734: /usr/bin/bash --execve--> 8752: /usr/bin/cp
8752: /usr/bin/cp --write--> 8753: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/meminfo.txt
8734: /usr/bin/bash --execve--> 8756: /usr/bin/ps
220: /etc/passwd --read--> 8756: /usr/bin/ps
1189: /etc/nsswitch.conf --read--> 8756: /usr/bin/ps
2530: /sys/devices/system/cpu/online --read--> 8756: /usr/bin/ps
8756: /usr/bin/ps --write--> 8755: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/process_rank.txt
8734: /usr/bin/bash --execve--> 8764: /usr/bin/ss
8764: /usr/bin/ss --write--> 8763: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/socket_snapshot.txt
8734: /usr/bin/bash --execve--> 8768: /usr/bin/dd
8768: /usr/bin/dd --write--> 8769: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/zero_blob.bin
8734: /usr/bin/bash --execve--> 8771: /usr/bin/dd
3230: /dev/urandom --read--> 8771: /usr/bin/dd
8771: /usr/bin/dd --write--> 8772: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/random_blob.bin
8734: /usr/bin/bash --execve--> 8775: /usr/bin/sha256sum
8769: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/zero_blob.bin --read--> 8775: /usr/bin/sha256sum
8775: /usr/bin/sha256sum --write--> 8774: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/zero.sha256
8734: /usr/bin/bash --execve--> 8778: /usr/bin/sha256sum
8772: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/random_blob.bin --read--> 8778: /usr/bin/sha256sum
8778: /usr/bin/sha256sum --write--> 8777: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/random.sha256
8734: /usr/bin/bash --execve--> 8781: /usr/bin/sha256sum
8769: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/zero_blob.bin --read--> 8781: /usr/bin/sha256sum
8781: /usr/bin/sha256sum --write--> 8780: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/repeat_hashes.txt
8734: /usr/bin/bash --execve--> 8783: /usr/bin/sha256sum
8769: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/zero_blob.bin --read--> 8783: /usr/bin/sha256sum
8783: /usr/bin/sha256sum --write--> 8780: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/repeat_hashes.txt
8734: /usr/bin/bash --execve--> 8785: /usr/bin/sha256sum
8769: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/zero_blob.bin --read--> 8785: /usr/bin/sha256sum
8785: /usr/bin/sha256sum --write--> 8780: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/repeat_hashes.txt
8734: /usr/bin/bash --execve--> 8787: /usr/bin/sha256sum
8769: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/zero_blob.bin --read--> 8787: /usr/bin/sha256sum
8787: /usr/bin/sha256sum --write--> 8780: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/repeat_hashes.txt
8734: /usr/bin/bash --execve--> 8789: /usr/bin/sha256sum
8772: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/random_blob.bin --read--> 8789: /usr/bin/sha256sum
8789: /usr/bin/sha256sum --write--> 8780: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/repeat_hashes.txt
8734: /usr/bin/bash --execve--> 8791: /usr/bin/sha256sum
8772: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/random_blob.bin --read--> 8791: /usr/bin/sha256sum
8791: /usr/bin/sha256sum --write--> 8780: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/repeat_hashes.txt
8734: /usr/bin/bash --execve--> 8793: /usr/bin/sha256sum
8772: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/random_blob.bin --read--> 8793: /usr/bin/sha256sum
8793: /usr/bin/sha256sum --write--> 8780: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/repeat_hashes.txt
8734: /usr/bin/bash --execve--> 8795: /usr/bin/sha256sum
8772: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/random_blob.bin --read--> 8795: /usr/bin/sha256sum
8795: /usr/bin/sha256sum --write--> 8780: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/repeat_hashes.txt
8734: /usr/bin/bash --execve--> 8798: /usr/bin/gzip
8755: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/process_rank.txt --read--> 8798: /usr/bin/gzip
8798: /usr/bin/gzip --write--> 8797: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/process_rank.txt.gz
8734: /usr/bin/bash --execve--> 8801: /usr/bin/gzip
8763: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/socket_snapshot.txt --read--> 8801: /usr/bin/gzip
8801: /usr/bin/gzip --write--> 8800: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/socket_snapshot.txt.gz
8734: /usr/bin/bash --execve--> 8803: /usr/bin/tar
8743: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/local_profile_copy.txt --read--> 8803: /usr/bin/tar
8747: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/remote_profile_copy.txt --read--> 8803: /usr/bin/tar
8750: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/cpuinfo.txt --read--> 8803: /usr/bin/tar
8753: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/meminfo.txt --read--> 8803: /usr/bin/tar
8755: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/process_rank.txt --read--> 8803: /usr/bin/tar
8763: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/socket_snapshot.txt --read--> 8803: /usr/bin/tar
8769: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/zero_blob.bin --read--> 8803: /usr/bin/tar
8772: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/samples/random_blob.bin --read--> 8803: /usr/bin/tar
8774: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/zero.sha256 --read--> 8803: /usr/bin/tar
8777: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/random.sha256 --read--> 8803: /usr/bin/tar
8780: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/hashes/repeat_hashes.txt --read--> 8803: /usr/bin/tar
8797: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/process_rank.txt.gz --read--> 8803: /usr/bin/tar
8800: /home/ubuntu/.local/share/progql-helper/runtime/run_20260602-160401/meta/socket_snapshot.txt.gz --read--> 8803: /usr/bin/tar
8803: /usr/bin/tar --execve--> 8808: /bin/sh
8808: /bin/sh --execve--> 8811: /usr/bin/gzip
8811: /usr/bin/gzip --write--> 8806: /home/ubuntu/.local/share/progql-helper/archive/run_20260602-160401.tar.gz



## 6. SQLite Pipeline Pollution

1438: /usr/bin/curl --sendto--> 1447: 192.168.122.129:33492->192.168.122.128:8085
1447: 192.168.122.129:33492->192.168.122.128:8085 --recvfrom--> 1438: /usr/bin/curl
1438: /usr/bin/curl --write--> 1448: /tmp/sync_client_bundle.tar.gz
1448: /tmp/sync_client_bundle.tar.gz --read--> 1467: /usr/bin/gzip
1467: /usr/bin/gzip --execve--> 1460: /usr/bin/tar
1460: /usr/bin/tar --write--> 1468: /tmp/progql_sync/install_sync.sh
1460: /usr/bin/tar --write--> 1469: /tmp/progql_sync/run_sync.sh
1460: /usr/bin/tar --write--> 1470: /tmp/progql_sync/sync_profile.txt
1468: /tmp/progql_sync/install_sync.sh --read--> 1473: /bin/bash
1473: /bin/bash --execve--> 1479: /usr/bin/mkdir
1473: /bin/bash --execve--> 1482: /usr/bin/cp
1469: /tmp/progql_sync/run_sync.sh --read--> 1482: /usr/bin/cp
1482: /usr/bin/cp --write--> 1484: /root/.local/share/progql-sync/run_sync.sh
1473: /bin/bash --execve--> 1486: /usr/bin/cp
1470: /tmp/progql_sync/sync_profile.txt --read--> 1486: /usr/bin/cp
1486: /usr/bin/cp --write--> 1487: /root/.local/share/progql-sync/sync_profile.txt
1473: /bin/bash --execve--> 1490: /usr/bin/chmod
1473: /bin/bash --execve--> 1493: /usr/bin/date
1473: /bin/bash --execve--> 1497: /usr/bin/mv
1484: /root/.local/share/progql-sync/run_sync.sh --read--> 1514: /bin/bash
1514: /bin/bash --execve--> 1520: /usr/bin/awk
1487: /root/.local/share/progql-sync/sync_profile.txt --read--> 1520: /usr/bin/awk
1514: /bin/bash --execve--> 1516: /usr/bin/mkdir
1514: /bin/bash --execve--> 1518: /usr/bin/date
1514: /bin/bash --execve--> 1522: /usr/bin/curl
1522: /usr/bin/curl --sendto--> 1523: 192.168.122.129:58010->192.168.122.128:8085
1523: 192.168.122.129:58010->192.168.122.128:8085 --recvfrom--> 1522: /usr/bin/curl
1522: /usr/bin/curl --write--> 1524: /root/.local/share/progql-sync/incoming/sqlite_pipeline_bundle.tar.gz
1514: /bin/bash --execve--> 1526: /usr/bin/tar
1526: /usr/bin/tar --execve--> 1528: /usr/bin/gzip
1524: /root/.local/share/progql-sync/incoming/sqlite_pipeline_bundle.tar.gz --read--> 1528: /usr/bin/gzip
1526: /usr/bin/tar --write--> 1529: /root/.local/share/progql-sync/incoming/template.txt
1526: /usr/bin/tar --write--> 1530: /root/.local/share/progql-sync/incoming/manifest.txt
1526: /usr/bin/tar --write--> 1531: /root/.local/share/progql-sync/incoming/assets.csv
1514: /bin/bash --execve--> 1533: /usr/bin/cp
1529: /root/.local/share/progql-sync/incoming/template.txt --read--> 1533: /usr/bin/cp
1533: /usr/bin/cp --write--> 1534: /root/.local/share/progql-sync/reports/template.txt
1514: /bin/bash --execve--> 1536: /usr/bin/cp
1530: /root/.local/share/progql-sync/incoming/manifest.txt --read--> 1536: /usr/bin/cp
1536: /usr/bin/cp --write--> 1537: /root/.local/share/progql-sync/reports/manifest.txt
1514: /bin/bash --execve--> 1548: /usr/bin/tail
1531: /root/.local/share/progql-sync/incoming/assets.csv --read--> 1548: /usr/bin/tail
1548: /usr/bin/tail --write--> 1547: /root/.local/share/progql-sync/incoming/assets_no_header.csv
1514: /bin/bash --execve--> 1543: /usr/bin/sqlite3
1541: /root/.local/share/progql-sync/work/assets.db --read--> 1543: /usr/bin/sqlite3
1514: /bin/bash --execve--> 1550: /usr/bin/sqlite3
1541: /root/.local/share/progql-sync/work/assets.db --read--> 1550: /usr/bin/sqlite3
1547: /root/.local/share/progql-sync/incoming/assets_no_header.csv --read--> 1550: /usr/bin/sqlite3
1514: /bin/bash --execve--> 1553: /usr/bin/sqlite3
1541: /root/.local/share/progql-sync/work/assets.db --read--> 1553: /usr/bin/sqlite3
1553: /usr/bin/sqlite3 --write--> 1552: /root/.local/share/progql-sync/reports/owner_summary.csv
1514: /bin/bash --execve--> 1556: /usr/bin/sqlite3
1541: /root/.local/share/progql-sync/work/assets.db --read--> 1556: /usr/bin/sqlite3
1556: /usr/bin/sqlite3 --write--> 1555: /root/.local/share/progql-sync/reports/group_summary.csv
1514: /bin/bash --execve--> 1559: /usr/bin/sqlite3
1541: /root/.local/share/progql-sync/work/assets.db --read--> 1559: /usr/bin/sqlite3
1559: /usr/bin/sqlite3 --write--> 1558: /root/.local/share/progql-sync/reports/high_score_assets.csv
1514: /bin/bash --execve--> 1562: /usr/bin/sqlite3
1541: /root/.local/share/progql-sync/work/assets.db --read--> 1562: /usr/bin/sqlite3
1562: /usr/bin/sqlite3 --write--> 1561: /root/.local/share/progql-sync/reports/tag_summary.csv
1514: /bin/bash --execve--> 1565: /usr/bin/awk
1558: /root/.local/share/progql-sync/reports/high_score_assets.csv --read--> 1565: /usr/bin/awk
1565: /usr/bin/awk --write--> 1564: /root/.local/share/progql-sync/reports/high_score_assets.pipe
1514: /bin/bash --execve--> 1568: /usr/bin/sed
1564: /root/.local/share/progql-sync/reports/high_score_assets.pipe --read--> 1568: /usr/bin/sed
1568: /usr/bin/sed --write--> 1567: /root/.local/share/progql-sync/reports/high_score_assets.rendered
1514: /bin/bash --execve--> 1571: /usr/bin/sort
1567: /root/.local/share/progql-sync/reports/high_score_assets.rendered --read--> 1571: /usr/bin/sort
1571: /usr/bin/sort --write--> 1570: /root/.local/share/progql-sync/reports/high_score_assets.sorted
1514: /bin/bash --execve--> 1575: /usr/bin/cat
1534: /root/.local/share/progql-sync/reports/template.txt --read--> 1575: /usr/bin/cat
1575: /usr/bin/cat --write--> 1573: /root/.local/share/progql-sync/final/current_report.txt
1514: /bin/bash --execve--> 1577: /usr/bin/cat
1552: /root/.local/share/progql-sync/reports/owner_summary.csv --read--> 1577: /usr/bin/cat
1577: /usr/bin/cat --write--> 1573: /root/.local/share/progql-sync/final/current_report.txt
1514: /bin/bash --execve--> 1579: /usr/bin/cat
1555: /root/.local/share/progql-sync/reports/group_summary.csv --read--> 1579: /usr/bin/cat
1579: /usr/bin/cat --write--> 1573: /root/.local/share/progql-sync/final/current_report.txt
1514: /bin/bash --execve--> 1581: /usr/bin/cat
1561: /root/.local/share/progql-sync/reports/tag_summary.csv --read--> 1581: /usr/bin/cat
1581: /usr/bin/cat --write--> 1573: /root/.local/share/progql-sync/final/current_report.txt
1514: /bin/bash --execve--> 1583: /usr/bin/cat
1570: /root/.local/share/progql-sync/reports/high_score_assets.sorted --read--> 1583: /usr/bin/cat
1583: /usr/bin/cat --write--> 1573: /root/.local/share/progql-sync/final/current_report.txt
1514: /bin/bash --write--> 1573: /root/.local/share/progql-sync/final/current_report.txt
1514: /bin/bash --execve--> 1586: /usr/bin/gzip
1552: /root/.local/share/progql-sync/reports/owner_summary.csv --read--> 1586: /usr/bin/gzip
1586: /usr/bin/gzip --write--> 1585: /root/.local/share/progql-sync/reports/owner_summary.csv.gz
1514: /bin/bash --execve--> 1589: /usr/bin/gzip
1555: /root/.local/share/progql-sync/reports/group_summary.csv --read--> 1589: /usr/bin/gzip
1589: /usr/bin/gzip --write--> 1588: /root/.local/share/progql-sync/reports/group_summary.csv.gz
1514: /bin/bash --execve--> 1592: /usr/bin/gzip
1558: /root/.local/share/progql-sync/reports/high_score_assets.csv --read--> 1592: /usr/bin/gzip
1592: /usr/bin/gzip --write--> 1591: /root/.local/share/progql-sync/reports/high_score_assets.csv.gz
1514: /bin/bash --execve--> 1596: /usr/bin/sha256sum
1555: /root/.local/share/progql-sync/reports/group_summary.csv --read--> 1596: /usr/bin/sha256sum
1588: /root/.local/share/progql-sync/reports/group_summary.csv.gz --read--> 1596: /usr/bin/sha256sum
1558: /root/.local/share/progql-sync/reports/high_score_assets.csv --read--> 1596: /usr/bin/sha256sum
1591: /root/.local/share/progql-sync/reports/high_score_assets.csv.gz --read--> 1596: /usr/bin/sha256sum
1564: /root/.local/share/progql-sync/reports/high_score_assets.pipe --read--> 1596: /usr/bin/sha256sum
1567: /root/.local/share/progql-sync/reports/high_score_assets.rendered --read--> 1596: /usr/bin/sha256sum
1570: /root/.local/share/progql-sync/reports/high_score_assets.sorted --read--> 1596: /usr/bin/sha256sum
1537: /root/.local/share/progql-sync/reports/manifest.txt --read--> 1596: /usr/bin/sha256sum
1552: /root/.local/share/progql-sync/reports/owner_summary.csv --read--> 1596: /usr/bin/sha256sum
1585: /root/.local/share/progql-sync/reports/owner_summary.csv.gz --read--> 1596: /usr/bin/sha256sum
1561: /root/.local/share/progql-sync/reports/tag_summary.csv --read--> 1596: /usr/bin/sha256sum
1534: /root/.local/share/progql-sync/reports/template.txt --read--> 1596: /usr/bin/sha256sum
1573: /root/.local/share/progql-sync/final/current_report.txt --read--> 1596: /usr/bin/sha256sum
1541: /root/.local/share/progql-sync/work/assets.db --read--> 1596: /usr/bin/sha256sum
1596: /usr/bin/sha256sum --write--> 1594: /root/.local/share/progql-sync/final/report.sha256
1514: /bin/bash --execve--> 1598: /usr/bin/tar
1530: /root/.local/share/progql-sync/incoming/manifest.txt --read--> 1598: /usr/bin/tar
1531: /root/.local/share/progql-sync/incoming/assets.csv --read--> 1598: /usr/bin/tar
1547: /root/.local/share/progql-sync/incoming/assets_no_header.csv --read--> 1598: /usr/bin/tar
1529: /root/.local/share/progql-sync/incoming/template.txt --read--> 1598: /usr/bin/tar
1524: /root/.local/share/progql-sync/incoming/sqlite_pipeline_bundle.tar.gz --read--> 1598: /usr/bin/tar
1541: /root/.local/share/progql-sync/work/assets.db --read--> 1598: /usr/bin/tar
1567: /root/.local/share/progql-sync/reports/high_score_assets.rendered --read--> 1598: /usr/bin/tar
1537: /root/.local/share/progql-sync/reports/manifest.txt --read--> 1598: /usr/bin/tar
1564: /root/.local/share/progql-sync/reports/high_score_assets.pipe --read--> 1598: /usr/bin/tar
1561: /root/.local/share/progql-sync/reports/tag_summary.csv --read--> 1598: /usr/bin/tar
1588: /root/.local/share/progql-sync/reports/group_summary.csv.gz --read--> 1598: /usr/bin/tar
1552: /root/.local/share/progql-sync/reports/owner_summary.csv --read--> 1598: /usr/bin/tar
1534: /root/.local/share/progql-sync/reports/template.txt --read--> 1598: /usr/bin/tar
1555: /root/.local/share/progql-sync/reports/group_summary.csv --read--> 1598: /usr/bin/tar
1585: /root/.local/share/progql-sync/reports/owner_summary.csv.gz --read--> 1598: /usr/bin/tar
1570: /root/.local/share/progql-sync/reports/high_score_assets.sorted --read--> 1598: /usr/bin/tar
1558: /root/.local/share/progql-sync/reports/high_score_assets.csv --read--> 1598: /usr/bin/tar
1591: /root/.local/share/progql-sync/reports/high_score_assets.csv.gz --read--> 1598: /usr/bin/tar
1573: /root/.local/share/progql-sync/final/current_report.txt --read--> 1598: /usr/bin/tar
1594: /root/.local/share/progql-sync/final/report.sha256 --read--> 1598: /usr/bin/tar
1598: /usr/bin/tar --execve--> 1603: /bin/sh
1603: /bin/sh --execve--> 1605: /usr/bin/gzip
1605: /usr/bin/gzip --write--> 1601: /root/.local/share/progql-sync/archive/sqlite_pipeline_final_20260602-162411.tar.gz