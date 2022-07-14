package apk

import (
	"bufio"
	"context"
	"log"
	"os"
	"path/filepath"

	apkVersion "github.com/knqyf263/go-apk-version"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&alpinePkgAnalyzer{})
}

const version = 1

var requiredFiles = []string{"lib/apk/db/installed"}

type alpinePkgAnalyzer struct{}

func (a alpinePkgAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	parsedPkgs, installedFiles := a.parseApkInfo(scanner)

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: parsedPkgs,
			},
		},
		SystemInstalledFiles: installedFiles,
	}, nil
}

func (a alpinePkgAnalyzer) parseApkInfo(scanner *bufio.Scanner) ([]types.Package, []types.SystemInstalledFiles) {
	var (
		pkgs           []types.Package
		pkg            types.Package
		version        string
		dir            string
		installedFiles []types.SystemInstalledFiles
	)

	for scanner.Scan() {
		line := scanner.Text()

		// check package if paragraph end
		if len(line) < 2 {
			if !pkg.Empty() {
				pkgs = append(pkgs, pkg)
			}
			pkg = types.Package{}
			continue
		}

		switch line[:2] {
		case "P:":
			pkg.Name = line[2:]
		case "V:":
			version = line[2:]
			if !apkVersion.Valid(version) {
				log.Printf("Invalid Version Found : OS %s, Package %s, Version %s", "alpine", pkg.Name, version)
				continue
			}
			pkg.Version = version
		case "o:":
			origin := line[2:]
			pkg.SrcName = origin
			pkg.SrcVersion = version
		case "L:":
			pkg.License = line[2:]
		case "F:":
			dir = line[2:]
		case "R:":
			fileInfo, err := os.Lstat(filepath.Join(dir, line[2:]))
			ino := utils.GetInode(fileInfo)
			if err != nil {
				continue
			}
			installedFiles = append(installedFiles, types.SystemInstalledFiles{FilePath: filepath.Join(dir, line[2:]), Inode: ino})
		}
	}
	// in case of last paragraph
	if !pkg.Empty() {
		pkgs = append(pkgs, pkg)
	}

	return a.uniquePkgs(pkgs), installedFiles
}

func (a alpinePkgAnalyzer) uniquePkgs(pkgs []types.Package) (uniqPkgs []types.Package) {
	uniq := map[string]struct{}{}
	for _, pkg := range pkgs {
		if _, ok := uniq[pkg.Name]; ok {
			continue
		}
		uniqPkgs = append(uniqPkgs, pkg)
		uniq[pkg.Name] = struct{}{}
	}
	return uniqPkgs
}

func (a alpinePkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a alpinePkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeApk
}

func (a alpinePkgAnalyzer) Version() int {
	return version
}
