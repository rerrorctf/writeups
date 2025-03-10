[KalmarCTF](https://ctftime.org/event/2599)

# Ez ⛳ v3 (web)

## Solution
This is a SSTI challenge in a config file. The vulnerable code is here:
```Caddyfile
respond /headers `{{ .Req.Header | mustToPrettyJson }}`
```

Every header gets reflected and `mustToPrettyJson` expands `{{ }}`.
So you just need to call ```{{ env `FLAG` }}``` neither `"'` work for the argument part but `` ` `` does.

## Flag
`kalmar{4n0th3r_K4lmarCTF_An0Th3R_C4ddy_Ch4ll}`

shafouz 2025/03/08
