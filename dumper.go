package main

import (
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"
)

type (
	Dumper struct {
		dir string
	}
	RoundTripDumper struct {
		Dumper
		http.RoundTripper
	}
	RoundTripNestedDumper struct {
		Dumper
		http.RoundTripper
	}
)

func (d RoundTripNestedDumper) RoundTrip(r *http.Request) (*http.Response, error) {
	ts := getTimeStamp()
	dumper, err := d.Dumper.Inner(ts)
	if err != nil {
		return nil, err
	}
	return RoundTripDumper{
		Dumper:       dumper,
		RoundTripper: d.RoundTripper,
	}.RoundTrip(r)
}

func (d RoundTripDumper) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := d.Dumper.Request(r, "request"); err != nil {
		return nil, err
	}
	resp, err := d.RoundTripper.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if err := d.Dumper.Response(resp, "response"); err != nil {
		return nil, err
	}
	return resp, nil
}

func getTimeStamp() string {
	u32 := rand.Uint32()
	nano := time.Now().UnixNano()
	return strconv.FormatInt(nano, 10) + "-" + strconv.FormatInt(int64(u32), 10)
}

func NewDumper(root string, name string) (Dumper, error) {
	dirpath := path.Join(root, name)
	err := os.MkdirAll(dirpath, 0777)
	if err != nil {
		return Dumper{}, err
	}
	return Dumper{
		dir: dirpath,
	}, nil
}
func (d Dumper) Dir() string {
	return d.dir
}
func (d Dumper) Inner(name string) (Dumper, error) {
	return NewDumper(d.dir, name)
}

func (d Dumper) Request(r *http.Request, title string) error {
	dirpath := path.Join(d.dir, title)
	err := os.MkdirAll(dirpath, 0777)
	if err != nil {
		return err
	}

	metaf, err := os.Create(path.Join(dirpath, "meta.json"))
	if err != nil {
		return err
	}
	defer metaf.Close()

	metaEncoder := json.NewEncoder(metaf)
	metaEncoder.SetIndent("", "  ")

	s := struct {
		Method           string
		URL              *url.URL
		Proto            string
		Header           http.Header
		ContentLength    int64
		TransferEncoding []string
		Close            bool
		Host             string
		Form             url.Values
		RemoteAddr       string
		RequestURI       string
	}{
		Method:           r.Method,
		URL:              r.URL,
		Proto:            r.Proto,
		Header:           r.Header,
		ContentLength:    r.ContentLength,
		TransferEncoding: r.TransferEncoding,
		Close:            r.Close,
		Host:             r.Host,
		Form:             r.Form,
		RemoteAddr:       r.RemoteAddr,
		RequestURI:       r.RequestURI,
	}

	err = metaEncoder.Encode(s)
	if err != nil {
		return err
	}

	if r.Body != nil {
		bodyf, err := os.Create(path.Join(dirpath, "body.bin"))
		if err != nil {
			return err
		}
		//_, err = bodyf.ReadFrom(r.Body)
		_, err = io.Copy(bodyf, r.Body)
		if err != nil {
			return err
		}
		r.Body.Close()
		bodyf.Seek(0, os.SEEK_SET)
		r.Body = bodyf
	}
	return nil
}
func (d Dumper) Response(r *http.Response, title string) error {
	dirpath := path.Join(d.dir, title)
	err := os.MkdirAll(dirpath, 0777)
	if err != nil {
		return err
	}

	metaf, err := os.Create(path.Join(dirpath, "meta.json"))
	if err != nil {
		return err
	}
	defer metaf.Close()

	metaEncoder := json.NewEncoder(metaf)
	metaEncoder.SetIndent("", "  ")
	s := struct {
		Status           string
		StatusCode       int
		Proto            string
		Header           http.Header
		ContentLength    int64
		TransferEncoding []string
		Close            bool
		Uncompressed     bool
	}{
		Status:           r.Status,
		StatusCode:       r.StatusCode,
		Proto:            r.Proto,
		Header:           r.Header,
		ContentLength:    r.ContentLength,
		TransferEncoding: r.TransferEncoding,
		Close:            r.Close,
		Uncompressed:     r.Uncompressed,
	}
	err = metaEncoder.Encode(s)
	if err != nil {
		return err
	}

	if r.Body != nil {
		bodyf, err := os.Create(path.Join(dirpath, "body.bin"))
		if err != nil {
			return err
		}
		_, err = io.Copy(bodyf, r.Body)
		//_, err = bodyf.ReadFrom(r.Body)
		if err != nil {
			return err
		}
		r.Body.Close()
		bodyf.Seek(0, os.SEEK_SET)
		r.Body = bodyf
	}
	return nil

}
