package bufmodule

import (
	"fmt"
	"sort"
	"strconv"
)

const (
	FileTypeProto FileType = iota + 1
	FileTypeDoc
	FileTypeLicense
)

var (
	fileTypeToString = map[FileType]string{
		FileTypeProto:   "proto",
		FileTypeDoc:     "doc",
		FileTypeLicense: "license",
	}
	stringToFileType = map[string]FileType{
		"proto":   FileTypeProto,
		"doc":     FileTypeDoc,
		"license": FileTypeLicense,
	}
)

type FileType int

func (c FileType) String() string {
	s, ok := fileTypeToString[c]
	if !ok {
		return strconv.Itoa(int(c))
	}
	return s
}

func ParseFileType(s string) (FileType, error) {
	c, ok := stringToFileType[s]
	if !ok {
		return 0, fmt.Errorf("unknown FileType: %q", s)
	}
	return c, nil
}

// *** PRIVATE ***

func fileTypeSliceToMap(fileTypes []FileType) map[FileType]struct{} {
	fileTypeMap := make(map[FileType]struct{})
	for _, fileType := range fileTypes {
		fileTypeMap[fileType] = struct{}{}
	}
	return fileTypeMap
}

func fileTypeMapToSortedSlice(fileTypeMap map[FileType]struct{}) []FileType {
	fileTypes := make([]FileType, 0, len(fileTypeMap))
	for fileType := range fileTypeMap {
		fileTypes = append(fileTypes, fileType)
	}
	sort.Slice(
		fileTypes,
		func(i int, j int) bool {
			return fileTypes[i] < fileTypes[j]
		},
	)
	return fileTypes
}
