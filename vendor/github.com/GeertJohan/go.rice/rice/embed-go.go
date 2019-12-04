package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"go/build"
	"go/format"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const boxFilename = "rice-box.go"

// errEmptyBox is returned by writeBoxesGo when no calls to rice.FindBox
// are found in the package.
var errEmptyBox = errors.New("no calls to rice.FindBox() found")

func writeBoxesGo(pkg *build.Package, out io.Writer) error {
	boxMap := findBoxes(pkg)

	if len(boxMap) == 0 {
		return errEmptyBox
	}

	verbosef("\n")

	var boxes []*boxDataType

	for boxname := range boxMap {
		// find path and filename for this box
		boxPath := filepath.Join(pkg.Dir, boxname)

		// Check to see if the path for the box is a symbolic link.  If so, simply
		// box what the symbolic link points to.  Note: the filepath.Walk function
		// will NOT follow any nested symbolic links.  This only handles the case
		// where the root of the box is a symbolic link.
		symPath, serr := os.Readlink(boxPath)
		if serr == nil {
			boxPath = symPath
		}

		// verbose info
		verbosef("embedding box '%s' to '%s'\n", boxname, boxFilename)

		// read box metadata
		boxInfo, ierr := os.Stat(boxPath)
		if ierr != nil {
			return fmt.Errorf("unable to access box at %s", boxPath)
		}

		// create box datastructure (used by template)
		box := &boxDataType{
			BoxName: boxname,
			UnixNow: boxInfo.ModTime().Unix(),
			Files:   make([]*fileDataType, 0),
			Dirs:    make(map[string]*dirDataType),
		}

		if !boxInfo.IsDir() {
			return fmt.Errorf("box %s must point to a directory but points to %s instead",
				boxname, boxPath)
		}

		// fill box datastructure with file data
		err := filepath.Walk(boxPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("error walking box: %s", err)
			}

			filename := strings.TrimPrefix(path, boxPath)
			filename = strings.Replace(filename, "\\", "/", -1)
			filename = strings.TrimPrefix(filename, "/")
			if info.IsDir() {
				dirData := &dirDataType{
					Identifier: "dir" + nextIdentifier(),
					FileName:   filename,
					ModTime:    info.ModTime().Unix(),
					ChildFiles: make([]*fileDataType, 0),
					ChildDirs:  make([]*dirDataType, 0),
				}
				verbosef("\tincludes dir: '%s'\n", dirData.FileName)
				box.Dirs[dirData.FileName] = dirData

				// add tree entry (skip for root, it'll create a recursion)
				if dirData.FileName != "" {
					pathParts := strings.Split(dirData.FileName, "/")
					parentDir := box.Dirs[strings.Join(pathParts[:len(pathParts)-1], "/")]
					parentDir.ChildDirs = append(parentDir.ChildDirs, dirData)
				}
			} else {
				fileData := &fileDataType{
					Identifier: "file" + nextIdentifier(),
					FileName:   filename,
					ModTime:    info.ModTime().Unix(),
				}
				verbosef("\tincludes file: '%s'\n", fileData.FileName)

				// Instead of injecting content, inject placeholder for fasttemplate.
				// This allows us to stream the content into the final file,
				// and it also avoids running gofmt on a very large source code.
				fileData.Path = path
				box.Files = append(box.Files, fileData)

				// add tree entry
				pathParts := strings.Split(fileData.FileName, "/")
				parentDir := box.Dirs[strings.Join(pathParts[:len(pathParts)-1], "/")]
				if parentDir == nil {
					return fmt.Errorf("parent of %s is not within the box", path)
				}
				parentDir.ChildFiles = append(parentDir.ChildFiles, fileData)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed in filepath walk: %v", err)
		}
		boxes = append(boxes, box)

	}

	embedSourceUnformated := bytes.NewBuffer(make([]byte, 0))

	// execute template to buffer
	err := tmplEmbeddedBox.Execute(
		embedSourceUnformated,
		embedFileDataType{pkg.Name, boxes},
	)
	if err != nil {
		return fmt.Errorf("error writing embedded box to file (template execute): %s", err)
	}

	// format the source code
	embedSource, err := format.Source(embedSourceUnformated.Bytes())
	if err != nil {
		return fmt.Errorf("error formatting embedSource: %s", err)
	}

	// write source to file
	bufWriter := bufio.NewWriterSize(out, 100*1024)
	err = embeddedBoxFasttemplate(bufWriter, string(embedSource))
	if err != nil {
		return fmt.Errorf("error writing embedSource to file: %s\n", err)
	}
	err = bufWriter.Flush()
	if err != nil {
		return fmt.Errorf("error writing embedSource to file: %s", err)
	}
	return nil
}

func operationEmbedGo(pkg *build.Package) {
	// create go file for box
	boxFile, err := os.Create(filepath.Join(pkg.Dir, boxFilename))
	if err != nil {
		log.Printf("error creating embedded box file: %s\n", err)
		os.Exit(1)
	}

	err = writeBoxesGo(pkg, boxFile)
	boxFile.Close()
	if err != nil {
		// don't leave an invalid go file in the package directory.
		if errRemove := os.Remove(boxFile.Name()); errRemove != nil {
			log.Printf("error while removing file: %s\n", errRemove)
		}
		if err != errEmptyBox {
			log.Printf("error creating embedded box file: %s\n", err)
			os.Exit(1)
		} else {
			// notify user when no calls to rice.FindBox are made,
			// but don't fail, since it's useful to be able to run
			// go.rice unconditionally.
			log.Println(errEmptyBox)
		}
	}
}
