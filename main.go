package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/sergi/go-diff/diffmatchpatch"
)

type FileInfo struct {
	Size        int64     `json:"size"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
	Accessed    time.Time `json:"accessed"`
	IsDirectory bool      `json:"isDirectory"`
	IsFile      bool      `json:"isFile"`
	Permissions string    `json:"permissions"`
}

type FilesystemServer struct {
	allowedDirs []string
	server      *server.MCPServer
}

// Add these new types to the type declarations section
type EditOperation struct {
	OldText string `json:"oldText"`
	NewText string `json:"newText"`
}

type EditFileArgs struct {
	Path   string          `json:"path"`
	Edits  []EditOperation `json:"edits"`
	DryRun bool            `json:"dryRun"`
}

func NewFilesystemServer(allowedDirs []string) (*FilesystemServer, error) {
	// Normalize and validate directories
	normalized := make([]string, 0, len(allowedDirs))
	for _, dir := range allowedDirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path %s: %w", dir, err)
		}

		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to access directory %s: %w",
				abs,
				err,
			)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("path is not a directory: %s", abs)
		}

		normalized = append(normalized, filepath.Clean(strings.ToLower(abs)))
	}

	s := &FilesystemServer{
		allowedDirs: normalized,
		server: server.NewMCPServer(
			"secure-filesystem-server",
			"0.2.0",
			server.WithToolCapabilities(true),
		),
	}

	// Register tool handlers
	s.server.AddTool(mcp.Tool{
		Name:        "read_file",
		Description: "Read the complete contents of a file from the file system.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to the file to read",
				},
			},
		},
	}, s.handleReadFile)

	s.server.AddTool(mcp.Tool{
		Name:        "write_file",
		Description: "Create a new file or overwrite an existing file with new content.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path where to write the file",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "Content to write to the file",
				},
			},
		},
	}, s.handleWriteFile)

	s.server.AddTool(mcp.Tool{
		Name:        "list_directory",
		Description: "Get a detailed listing of all files and directories in a specified path.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path of the directory to list",
				},
			},
		},
	}, s.handleListDirectory)

	s.server.AddTool(mcp.Tool{
		Name:        "create_directory",
		Description: "Create a new directory or ensure a directory exists.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path of the directory to create",
				},
			},
		},
	}, s.handleCreateDirectory)

	s.server.AddTool(mcp.Tool{
		Name:        "move_file",
		Description: "Move or rename files and directories.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"source": map[string]interface{}{
					"type":        "string",
					"description": "Source path of the file or directory",
				},
				"destination": map[string]interface{}{
					"type":        "string",
					"description": "Destination path",
				},
			},
		},
	}, s.handleMoveFile)

	s.server.AddTool(mcp.Tool{
		Name:        "search_files",
		Description: "Recursively search for files and directories matching a pattern.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Starting path for the search",
				},
				"pattern": map[string]interface{}{
					"type":        "string",
					"description": "Search pattern to match against file names",
				},
			},
		},
	}, s.handleSearchFiles)

	s.server.AddTool(mcp.Tool{
		Name:        "get_file_info",
		Description: "Retrieve detailed metadata about a file or directory.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to the file or directory",
				},
			},
		},
	}, s.handleGetFileInfo)

	s.server.AddTool(mcp.Tool{
		Name:        "list_allowed_directories",
		Description: "Returns the list of directories that this server is allowed to access.",
		InputSchema: mcp.ToolInputSchema{
			Type:       "object",
			Properties: map[string]interface{}{},
		},
	}, s.handleListAllowedDirectories)

	// Add this to the NewFilesystemServer function after the other tool registrations
	s.server.AddTool(mcp.Tool{
		Name: "edit_file",
		Description: "Make line-based edits to a text file. Each edit replaces exact line sequences " +
			"with new content. Returns a git-style diff showing the changes made. " +
			"Only works within allowed directories.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path of the file to edit",
				},
				"edits": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"oldText": map[string]interface{}{
								"type":        "string",
								"description": "Text to search for - must match exactly",
							},
							"newText": map[string]interface{}{
								"type":        "string",
								"description": "Text to replace with",
							},
						},
						"required": []string{"oldText", "newText"},
					},
				},
				"dryRun": map[string]interface{}{
					"type":        "boolean",
					"description": "Preview changes using git-style diff format",
					"default":     false,
				},
			},
		},
	}, s.handleEditFile)

	return s, nil
}

func (s *FilesystemServer) validatePath(requestedPath string) (string, error) {
	abs, err := filepath.Abs(requestedPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	normalized := filepath.Clean(strings.ToLower(abs))

	// Check if path is within allowed directories
	allowed := false
	for _, dir := range s.allowedDirs {
		if strings.HasPrefix(normalized, dir) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf(
			"access denied - path outside allowed directories: %s",
			abs,
		)
	}

	// Handle symlinks
	realPath, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		// For new files, check parent directory
		parent := filepath.Dir(abs)
		realParent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return "", fmt.Errorf("parent directory does not exist: %s", parent)
		}
		normalizedParent := filepath.Clean(strings.ToLower(realParent))
		for _, dir := range s.allowedDirs {
			if strings.HasPrefix(normalizedParent, dir) {
				return abs, nil
			}
		}
		return "", fmt.Errorf(
			"access denied - parent directory outside allowed directories",
		)
	}

	normalizedReal := filepath.Clean(strings.ToLower(realPath))
	for _, dir := range s.allowedDirs {
		if strings.HasPrefix(normalizedReal, dir) {
			return realPath, nil
		}
	}
	return "", fmt.Errorf(
		"access denied - symlink target outside allowed directories",
	)
}

func (s *FilesystemServer) getFileStats(path string) (FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileInfo{}, err
	}

	return FileInfo{
		Size:        info.Size(),
		Created:     info.ModTime(), // Note: ModTime used as birth time isn't always available
		Modified:    info.ModTime(),
		Accessed:    info.ModTime(), // Note: Access time isn't always available
		IsDirectory: info.IsDir(),
		IsFile:      !info.IsDir(),
		Permissions: fmt.Sprintf("%o", info.Mode().Perm()),
	}, nil
}

func (s *FilesystemServer) searchFiles(
	rootPath, pattern string,
) ([]string, error) {
	var results []string
	pattern = strings.ToLower(pattern)

	err := filepath.Walk(
		rootPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip errors and continue
			}

			// Try to validate path
			if _, err := s.validatePath(path); err != nil {
				return nil // Skip invalid paths
			}

			if strings.Contains(strings.ToLower(info.Name()), pattern) {
				results = append(results, path)
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// Add these utility functions
func normalizeLineEndings(text string) string {
	return strings.ReplaceAll(text, "\r\n", "\n")
}

func createUnifiedDiff(originalContent, newContent, filepath string) string {
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(originalContent, newContent, true)
	patch := dmp.PatchMake(diffs)
	patchText := dmp.PatchToText(patch)

	var result strings.Builder
	result.WriteString("diff --git a/" + filepath + " b/" + filepath + "\n")
	result.WriteString("--- a/" + filepath + "\n")
	result.WriteString("+++ b/" + filepath + "\n")
	result.WriteString(patchText)

	return result.String()
}

func applyFileEdits(filePath string, edits []EditOperation, dryRun bool) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	modifiedContent := normalizeLineEndings(string(content))

	// Apply edits sequentially
	for _, edit := range edits {
		normalizedOld := normalizeLineEndings(edit.OldText)
		normalizedNew := normalizeLineEndings(edit.NewText)

		// Try exact match first
		if strings.Contains(modifiedContent, normalizedOld) {
			modifiedContent = strings.Replace(modifiedContent, normalizedOld, normalizedNew, 1)
			continue
		}

		// Try line-by-line matching with whitespace flexibility
		oldLines := strings.Split(normalizedOld, "\n")
		contentLines := strings.Split(modifiedContent, "\n")
		matchFound := false

		for i := 0; i <= len(contentLines)-len(oldLines); i++ {
			potentialMatch := contentLines[i : i+len(oldLines)]
			isMatch := true

			for j, oldLine := range oldLines {
				if strings.TrimSpace(oldLine) != strings.TrimSpace(potentialMatch[j]) {
					isMatch = false
					break
				}
			}

			if isMatch {
				// Preserve original indentation of first line
				originalIndent := ""
				if indentMatch := regexp.MustCompile(`^\s*`).FindString(contentLines[i]); indentMatch != "" {
					originalIndent = indentMatch
				}

				// Split new content and handle indentation
				newLines := strings.Split(normalizedNew, "\n")
				for j, line := range newLines {
					if j == 0 {
						newLines[j] = originalIndent + strings.TrimLeft(line, " \t")
					} else {
						// For subsequent lines, try to preserve relative indentation
						oldIndent := regexp.MustCompile(`^\s*`).FindString(oldLines[j])
						newIndent := regexp.MustCompile(`^\s*`).FindString(line)
						relativeIndent := len(newIndent) - len(oldIndent)
						if relativeIndent > 0 {
							newLines[j] = originalIndent + strings.Repeat(" ", relativeIndent) + strings.TrimLeft(line, " \t")
						} else {
							newLines[j] = originalIndent + strings.TrimLeft(line, " \t")
						}
					}
				}

				// Replace the matching lines with the new content
				newContent := strings.Join(newLines, "\n")
				beforeLines := contentLines[:i]
				afterLines := contentLines[i+len(oldLines):]
				contentLines = append(beforeLines, append([]string{newContent}, afterLines...)...)
				modifiedContent = strings.Join(contentLines, "\n")
				matchFound = true
				break
			}
		}

		if !matchFound {
			return "", fmt.Errorf("could not find exact match for edit:\n%s", edit.OldText)
		}
	}

	// Create unified diff
	diff := createUnifiedDiff(string(content), modifiedContent, filePath)

	// Format diff output
	var numBackticks int = 3
	for strings.Contains(diff, strings.Repeat("`", numBackticks)) {
		numBackticks++
	}
	formattedDiff := fmt.Sprintf("%s\n%s%s\n\n",
		strings.Repeat("`", numBackticks),
		diff,
		strings.Repeat("`", numBackticks))

	if !dryRun {
		err = os.WriteFile(filePath, []byte(modifiedContent), 0644)
		if err != nil {
			return "", err
		}
	}

	return formattedDiff, nil
}

// Tool handlers

func (s *FilesystemServer) handleEditFile(arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	// Parse and validate arguments
	jsonData, err := json.Marshal(arguments)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal arguments: %w", err)
	}

	var args EditFileArgs
	if err := json.Unmarshal(jsonData, &args); err != nil {
		return nil, fmt.Errorf("failed to parse arguments: %w", err)
	}

	// Validate path
	validPath, err := s.validatePath(args.Path)
	if err != nil {
		return nil, err
	}

	// Apply edits
	diff, err := applyFileEdits(validPath, args.Edits, args.DryRun)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("Error editing file: %v", err),
				},
			},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []interface{}{
			mcp.TextContent{
				Type: "text",
				Text: diff,
			},
		},
	}, nil
}

func (s *FilesystemServer) handleReadFile(
	arguments map[string]interface{},
) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path must be a string")
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	content, err := os.ReadFile(validPath)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("Error reading file: %v", err),
				},
			},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []interface{}{
			mcp.TextContent{
				Type: "text",
				Text: string(content),
			},
		},
	}, nil
}

func (s *FilesystemServer) handleWriteFile(
	arguments map[string]interface{},
) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path must be a string")
	}
	content, ok := arguments["content"].(string)
	if !ok {
		return nil, fmt.Errorf("content must be a string")
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(validPath, []byte(content), 0644); err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("Error writing file: %v", err),
				},
			},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []interface{}{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("Successfully wrote to %s", path),
			},
		},
	}, nil
}

func (s *FilesystemServer) handleListDirectory(
	arguments map[string]interface{},
) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path must be a string")
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(validPath)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("Error reading directory: %v", err),
				},
			},
			IsError: true,
		}, nil
	}

	var result strings.Builder
	for _, entry := range entries {
		prefix := "[FILE]"
		if entry.IsDir() {
			prefix = "[DIR]"
		}
		fmt.Fprintf(&result, "%s %s\n", prefix, entry.Name())
	}

	return &mcp.CallToolResult{
		Content: []interface{}{
			mcp.TextContent{
				Type: "text",
				Text: result.String(),
			},
		},
	}, nil
}

func (s *FilesystemServer) handleCreateDirectory(
	arguments map[string]interface{},
) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path must be a string")
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(validPath, 0755); err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("Error creating directory: %v", err),
				},
			},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []interface{}{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("Successfully created directory %s", path),
			},
		},
	}, nil
}

func (s *FilesystemServer) handleMoveFile(
	arguments map[string]interface{},
) (*mcp.CallToolResult, error) {
	source, ok := arguments["source"].(string)
	if !ok {
		return nil, fmt.Errorf("source must be a string")
	}
	destination, ok := arguments["destination"].(string)
	if !ok {
		return nil, fmt.Errorf("destination must be a string")
	}

	validSource, err := s.validatePath(source)
	if err != nil {
		return nil, err
	}
	validDest, err := s.validatePath(destination)
	if err != nil {
		return nil, err
	}

	if err := os.Rename(validSource, validDest); err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("Error moving file: %v", err),
				},
			},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []interface{}{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf(
					"Successfully moved %s to %s",
					source,
					destination,
				),
			},
		},
	}, nil
}

func (s *FilesystemServer) handleSearchFiles(
	arguments map[string]interface{},
) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path must be a string")
	}
	pattern, ok := arguments["pattern"].(string)
	if !ok {
		return nil, fmt.Errorf("pattern must be a string")
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	results, err := s.searchFiles(validPath, pattern)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("Error searching files: %v",
						err),
				},
			},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []interface{}{
			mcp.TextContent{
				Type: "text",
				Text: strings.Join(results, "\n"),
			},
		},
	}, nil
}

func (s *FilesystemServer) handleGetFileInfo(
	arguments map[string]interface{},
) (*mcp.CallToolResult, error) {
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path must be a string")
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		return nil, err
	}

	info, err := s.getFileStats(validPath)
	if err != nil {
		return &mcp.CallToolResult{
			Content: []interface{}{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("Error getting file info: %v", err),
				},
			},
			IsError: true,
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []interface{}{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf(
					"Size: %d\nCreated: %s\nModified: %s\nAccessed: %s\nIsDirectory: %v\nIsFile: %v\nPermissions: %s",
					info.Size,
					info.Created.Format(time.RFC3339),
					info.Modified.Format(time.RFC3339),
					info.Accessed.Format(time.RFC3339),
					info.IsDirectory,
					info.IsFile,
					info.Permissions,
				),
			},
		},
	}, nil
}

func (s *FilesystemServer) handleListAllowedDirectories(
	arguments map[string]interface{},
) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		Content: []interface{}{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf(
					"Allowed directories:\n%s",
					strings.Join(s.allowedDirs, "\n"),
				),
			},
		},
	}, nil
}

func (s *FilesystemServer) Serve() error {
	return server.ServeStdio(s.server)
}

func main() {
	// Parse command line arguments
	if len(os.Args) < 2 {
		fmt.Fprintf(
			os.Stderr,
			"Usage: %s <allowed-directory> [additional-directories...]\n",
			os.Args[0],
		)
		os.Exit(1)
	}

	// Create and start the server
	fs, err := NewFilesystemServer(os.Args[1:])
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Serve requests
	if err := fs.Serve(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
