package ISV

import (
	"os/exec"
	"sig_vfy/src/base"
	"time"

	"github.com/beevik/ntp"
)

func getNTPTime(ntpServer string) (time.Time, *base.StdErr) {
	ntpTime, err := ntp.Time(ntpServer)
	if err != nil {
		return time.Time{}, base.CreateStdErr(base.GM_NTP_CONNECT_ERROR,
			"Connect NTPServer Error Code [%08X]", base.GM_NTP_CONNECT_ERROR)
	}
	return ntpTime, nil
}

func getTimeDiff(ntpTime time.Time) time.Duration {
	diff := time.Since(ntpTime)
	if diff < 0 {
		return -diff
	}
	return diff
}

func CheckAndSyncSystemTime(ntpServer string) *base.StdErr {
	ntptime, stderr := getNTPTime(ntpServer)
	if stderr != nil {
		return stderr
	}

	diff := getTimeDiff(ntptime)

	if diff > time.Minute {
		dateStr := ntptime.Format("2006-01-02 15:04:05")
		cmd := exec.Command("sudo", "date", "-s", dateStr)
		err := cmd.Run()
		if err != nil {
			return base.CreateStdErr(base.GM_NTP_SYNC_ERROR,
				"Sync NTP Time Error Code [%08X]", base.GM_NTP_SYNC_ERROR)
		}
	}
	return nil
}
