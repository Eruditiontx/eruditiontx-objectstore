// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Developer: Allan Ninal

package cmd

import (
	"archive/tar"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/minio/minio-go/v7/pkg/signer"
	xhttp "github.com/minio/minio/internal/http"
)

// Regression tests for CVE-2026-40344 and CVE-2026-41145: an unsigned-trailer
// upload that names an access key must have its signature verified. Each test
// sends such a request without a valid signature and checks that it is
// rejected and that nothing was written.
func TestUnsignedTrailerRequiresSignature(t *testing.T) {
	s := &TestSuiteCommon{serverType: "ErasureSD", signer: signerV4}
	c := &check{t, s.serverType}
	s.SetUpSuite(c)
	defer s.TearDownSuite(c)

	s.testUnsignedTrailerQueryCredentialsPutObject(c)
	s.testUnsignedTrailerQueryCredentialsPutObjectPart(c)
	s.testUnsignedTrailerSnowballExtract(c)
}

func (s *TestSuiteCommon) makeTestBucket(c *check) string {
	c.Helper()
	bucketName := getRandomBucketName()
	request, err := newTestSignedRequest(http.MethodPut, getMakeBucketURL(s.endPoint, bucketName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)
	response, err := s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)
	return bucketName
}

func (s *TestSuiteCommon) headObjectStatus(c *check, bucketName, objectName string) int {
	c.Helper()
	request, err := newTestSignedRequest(http.MethodHead, getHeadObjectURL(s.endPoint, bucketName, objectName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)
	response, err := s.client.Do(request)
	c.Assert(err, nil)
	return response.StatusCode
}

// newQueryCredentialUnsignedTrailerRequest builds an aws-chunked unsigned-trailer
// PUT that carries the access key only in the X-Amz-Credential query parameter
// and has no Authorization header.
func (s *TestSuiteCommon) newQueryCredentialUnsignedTrailerRequest(c *check, targetURL string, body []byte) *http.Request {
	c.Helper()
	now := UTCNow()
	q := url.Values{}
	q.Set(xhttp.AmzCredential, fmt.Sprintf("%s/%s/us-east-1/s3/aws4_request", s.accessKey, now.Format(yyyymmdd)))
	sep := "?"
	if u, err := url.Parse(targetURL); err == nil && u.RawQuery != "" {
		sep = "&"
	}

	req, err := http.NewRequest(http.MethodPut, targetURL+sep+q.Encode(), nil)
	c.Assert(err, nil)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.Trailer = http.Header{}
	req.Trailer.Set("x-amz-checksum-crc32", "rK0DXg==")
	req = signer.StreamingUnsignedV4(req, "", int64(len(body)), now)
	req.Header.Del(xhttp.Authorization)
	req.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprint(len(body)))
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32")
	req.Header.Set(xhttp.AmzContentSha256, unsignedPayloadTrailer)
	return req
}

// CVE-2026-41145, PutObjectHandler.
func (s *TestSuiteCommon) testUnsignedTrailerQueryCredentialsPutObject(c *check) {
	c.Helper()
	bucketName := s.makeTestBucket(c)
	objectName := "query-credential-object.txt"

	req := s.newQueryCredentialUnsignedTrailerRequest(c, getPutObjectURL(s.endPoint, bucketName, objectName), []byte("foobar!\n"))
	response, err := s.client.Do(req)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusBadRequest)

	c.Assert(s.headObjectStatus(c, bucketName, objectName), http.StatusNotFound)
}

// CVE-2026-41145, PutObjectPartHandler.
func (s *TestSuiteCommon) testUnsignedTrailerQueryCredentialsPutObjectPart(c *check) {
	c.Helper()
	bucketName := s.makeTestBucket(c)
	objectName := "query-credential-multipart-object"

	request, err := newTestSignedRequest(http.MethodPost, getNewMultipartURL(s.endPoint, bucketName, objectName),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)
	response, err := s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)
	initiated := &InitiateMultipartUploadResponse{}
	c.Assert(xml.NewDecoder(response.Body).Decode(initiated), nil)

	req := s.newQueryCredentialUnsignedTrailerRequest(c,
		getPutObjectPartURL(s.endPoint, bucketName, objectName, initiated.UploadID, "1"), []byte("foobar!\n"))
	response, err = s.client.Do(req)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusBadRequest)

	request, err = newTestSignedRequest(http.MethodGet,
		getListMultipartURLWithParams(s.endPoint, bucketName, objectName, initiated.UploadID, "", "", ""),
		0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)
	response, err = s.client.Do(request)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusOK)
	parts := &ListPartsResponse{}
	c.Assert(xml.NewDecoder(response.Body).Decode(parts), nil)
	c.Assert(len(parts.Parts), 0)
}

// CVE-2026-40344, PutObjectExtractHandler (snowball auto-extract).
func (s *TestSuiteCommon) testUnsignedTrailerSnowballExtract(c *check) {
	c.Helper()
	bucketName := s.makeTestBucket(c)
	extractedName := "extracted-object.txt"

	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	content := []byte("foobar!\n")
	c.Assert(tw.WriteHeader(&tar.Header{Name: extractedName, Mode: 0o600, Size: int64(len(content))}), nil)
	_, err := tw.Write(content)
	c.Assert(err, nil)
	c.Assert(tw.Close(), nil)

	req, err := http.NewRequest(http.MethodPut, getPutObjectURL(s.endPoint, bucketName, "archive.tar"), bytes.NewReader(archive.Bytes()))
	c.Assert(err, nil)
	req.ContentLength = int64(archive.Len())
	now := UTCNow()
	req.Header.Set(xhttp.Authorization, fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=%064x", s.accessKey, now.Format(yyyymmdd), 0))
	req.Header.Set(xhttp.AmzDate, now.Format(iso8601Format))
	req.Header.Set(xhttp.AmzContentSha256, unsignedPayloadTrailer)
	req.Header.Set(xhttp.AmzSnowballExtract, "true")

	response, err := s.client.Do(req)
	c.Assert(err, nil)
	c.Assert(response.StatusCode, http.StatusBadRequest)

	c.Assert(s.headObjectStatus(c, bucketName, extractedName), http.StatusNotFound)
}
