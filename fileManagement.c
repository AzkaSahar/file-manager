#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <pthread.h>
#include<limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdbool.h>
#define MAX_FILES 1024
#define MAX_KEYWORDS 1000
#define LEN 15
#define MAX 256
#define THREAD_COUNT 8

pthread_mutex_t mutex;


// Define buffer size
#define BUFFER_SIZE 1024


// Define named pipe paths
#define DPIPE_PATH "/tmp/decryption_pipe"


// Define mutex and semaphores
pthread_mutex_t dpipe_mutex = PTHREAD_MUTEX_INITIALIZER;
sem_t semd1, semd2, semd3;


// Global variable to store file (decryption)
char file_ddata[BUFFER_SIZE];
uint32_t hash_value_d;
size_t bytes_read_d;
char *file_name;


// Define named pipe paths
#define PIPE_PATH "/tmp/encryption_pipe"


// Define mutex and semaphores
pthread_mutex_t epipe_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;
sem_t sem1, sem2;


// Global variable to store file data(ecnryption)
char file_data[BUFFER_SIZE];
uint32_t hash_value;
size_t bytes_read;
char *file_name;



// Function to create a new file in the specified directory
void createfile(const char *directory) {
	char filename[FILENAME_MAX];
	printf("Enter the name of the new file: ");
	scanf("%s", filename);


	char filepath[PATH_MAX];
	strcpy(filepath, directory);
	strcat(filepath, "/");
	strcat(filepath, filename);

   pthread_mutex_lock(&mutex);
	FILE *file = fopen(filepath, "w");
	if (file == NULL) {
  	  perror("Error creating file");
  	  return;
	}
	fclose(file);
	printf("File '%s' created successfully.\n", filename);
	pthread_mutex_unlock(&mutex);
}


// Function to delete a file in the specified directory
void deletefile(const char *directory) {
	char filename[FILENAME_MAX];
	printf("Enter the name of the file to delete: ");
	scanf("%s", filename);


	char filepath[PATH_MAX];
	strcpy(filepath, directory);
	strcat(filepath, "/");
	strcat(filepath, filename);
    
	pthread_mutex_lock(&mutex);
	if (remove(filepath) == 0) {
  	  printf("File '%s' deleted successfully.\n", filename);
	} else {
  	  perror("Error deleting file");
	}
	pthread_mutex_unlock(&mutex);
}


// Function to rename a file in the specified directory
void renamefile(const char *directory) {
	char oldname[FILENAME_MAX];
	printf("Enter the name of the file to rename: ");
	scanf("%s", oldname);


	char newname[FILENAME_MAX];
	printf("Enter the new name for the file: ");
	scanf("%s", newname);


	char oldpath[PATH_MAX];
	strcpy(oldpath, directory);
	strcat(oldpath, "/");
	strcat(oldpath, oldname);


	char newpath[PATH_MAX];
	strcpy(newpath, directory);
	strcat(newpath, "/");
	strcat(newpath, newname);
    
	pthread_mutex_lock(&mutex);
	if (rename(oldpath, newpath) == 0) {
  	  printf("File '%s' renamed to '%s' successfully.\n", oldname, newname);
	} else {
  	  perror("Error renaming file");
	}
	pthread_mutex_unlock(&mutex);
}







// DECRYPTION PROCESS
void *read_ddata(void *arg) {
	file_name = (char *)arg;
	// Open file for reading
	FILE *file = fopen(file_name, "rb");
	if (file == NULL) {
  	  perror("Error opening file");
  	  exit(EXIT_FAILURE);
	}
	// Read data from file
	bytes_read_d = fread(file_ddata, 1, BUFFER_SIZE, file);
	for (int i=0; i<25; i++) {
  	  printf("%c", file_ddata[i]);
	}

	fclose(file);
	sem_post(&semd1);
	return NULL;
}


// Function to decrypt data using simple XOR encryption
void *decrypt_data(void *arg) {
	sem_wait(&semd1);
	sem_wait(&semd3);


	ssize_t x;
	for (int i = 0; i < strlen(file_ddata); i++) {
  	  file_ddata[i] ^= (hash_value_d & 0xFF); // Use lower 8 bits of hash as key
  	  printf("%c", file_ddata[i]);
	}
	pthread_mutex_lock(&dpipe_mutex);
	int pipe_fd = open(DPIPE_PATH, O_WRONLY);
	if (pipe_fd == -1) {
  	  perror("Error opening named pipe for writing");
  	  exit(EXIT_FAILURE);
	}
	fflush(stdout);
	x = write(pipe_fd, file_ddata, strlen(file_ddata));
	if (x == -1) {
  	  perror("Error writing to named pipe");
  	  exit(EXIT_FAILURE);
	}
	// Close named pipe
	if (close(pipe_fd) == -1) {
	perror("Error closing named pipe");
	}
   
	pthread_mutex_unlock(&dpipe_mutex);
	sem_post(&semd2); // Signal write_decrypted_data to proceed
	return NULL;
}


// Function to write decrypted data to file
void *write_decrypted_data(void *arg) {
	file_name = (char *)arg;
	char buffer[BUFFER_SIZE];

	sem_wait(&semd2);
	// Open named pipe for reading
	pthread_mutex_lock(&dpipe_mutex);
	int pipe_fd = open(DPIPE_PATH, O_RDWR);
	if (pipe_fd == -1) {
  	  perror("Error opening named pipe");
  	  exit(EXIT_FAILURE);
	}
	else {
  	  write(1, "opened pipe\n", 12);
	}


	// Read decrypted data from named pipe and write to file
	bytes_read_d = read(pipe_fd, buffer, BUFFER_SIZE);
	if ( bytes_read_d== -1) {
  	  perror("Error reading from named pipe");
  	  exit(EXIT_FAILURE);
	}
	// Close named pipe
	if (close(pipe_fd) == -1) {
	perror("Error closing named pipe");
	}
	pthread_mutex_unlock(&dpipe_mutex);
	// Open file for writing
	FILE *file = fopen(file_name, "wb");
	if (file == NULL) {
  	  perror("Error opening file");
  	  exit(EXIT_FAILURE);
	}


	fwrite(buffer, 1, bytes_read_d, file);

	// Close file
	fclose(file);
	return NULL;
}


// Function to read hash value from hash values file
void *read_hash_value(void *arg) {
	file_name = (char *)arg;


	// Open hash values file for reading
	FILE *hash_file = fopen("hash_values.txt", "r");
	if (hash_file == NULL) {
  	  perror("Error opening hash values file");
  	  exit(EXIT_FAILURE);
	}
	char line[256];
	bool found = false;
	while (fgets(line, sizeof(line),hash_file)) {
  	  char old_file_name[256];
  	  uint32_t old_hash_value;
  	  sscanf(line, "%255[^,],%u", old_file_name, &old_hash_value);


  	  if (strcmp(old_file_name, file_name) == 0) {
  		  // Found hash value for the specified file
  		  hash_value_d = old_hash_value;
  		  found = true;
  		  break;
  	  }
	}
	fclose(hash_file);
	if (!found) {
  	  fprintf(stderr, "Hash value not found for file: %s\n", file_name);
  	  exit(EXIT_FAILURE);
	}
	sem_post(&semd3); // Signal decrypt_data to proceed


	return NULL;
}

  void decryption(char *filename) {
	fflush(stdout);


	// Create named pipe
	mkfifo(DPIPE_PATH, 0666);


	// Initialize semaphore
	sem_init(&semd1, 0, 0);
	sem_init(&semd2, 0, 0);
	sem_init(&semd3, 0, 0);

	// Create threads
	pthread_t readd_thread, decrypt_thread, write_thread, readh_thread;
	pthread_create(&readd_thread, NULL, read_ddata, filename);
	pthread_create(&decrypt_thread, NULL, decrypt_data, NULL);
	pthread_create(&write_thread, NULL, write_decrypted_data, filename);
	pthread_create(&readh_thread, NULL, read_hash_value, filename);


	// Run cat command to read from the pipe
	system("gnome-terminal -- /bin/sh -c 'cat /tmp/decryption_pipe'");


	// Join threads
	pthread_join(readd_thread, NULL);
	pthread_join(decrypt_thread, NULL);
	pthread_join(write_thread, NULL);
	pthread_join(readh_thread, NULL);


	// Destroy mutex and semaphore
	pthread_mutex_destroy(&dpipe_mutex);
	sem_destroy(&semd1);
	sem_destroy(&semd2);
	sem_destroy(&semd3);


	// Remove named pipe
	unlink(DPIPE_PATH);
}










// Hash
uint32_t crc32(const void *data, size_t n_bytes) {
	const uint8_t *p = data;
	uint32_t crc = 0xFFFFFFFF;
	while (n_bytes--) {
  	  crc ^= *p++;
  	  for (int i = 0; i < 8; i++) {
  		  crc = (crc >> 1) ^ ((crc & 1) * 0xEDB88320);
  	  }
	}
	return ~crc;
}


// Check if the file name exists in the hash file
bool file_name_exists(const char *hash_file_name, const char *file_name) {
	FILE *hash_file = fopen(hash_file_name, "r");
	if (hash_file == NULL) {
  	  return false; // File doesn't exist, so file name doesn't exist
	}
	char line[256];
	while (fgets(line, sizeof(line), hash_file)) {
  	  char old_file_name[256];
  	  uint32_t old_hash_value;
  	  sscanf(line, "%255[^,],%u", old_file_name, &old_hash_value);
  	  if (strcmp(old_file_name, file_name) == 0) {
  		  fseek(hash_file, -strlen(line), SEEK_CUR);
  		  fprintf(hash_file, "%s,%u\n", file_name, hash_value);
  		  fclose(hash_file);
  		  return true; // File name already exists in the file
  	  }
	}
	fclose(hash_file);
	return false; // File name doesn't exist in the file
}





// Function to read data from file
void *read_data(void *arg) {
	file_name = (char *)arg;


	// Open file for reading
	FILE *file = fopen(file_name, "rb");
	if (file == NULL) {
  	  perror("Error opening file");
  	  exit(EXIT_FAILURE);
	}
	// Read data from file
	bytes_read = fread(file_data, 1, BUFFER_SIZE, file);
	fclose(file);
	hash_value = crc32(file_data, strlen(file_data));
	printf("Hash Value: %u\n", hash_value);
	sem_post(&sem1);
	return NULL;
}


// Function to encrypt data using simple XOR encryption
void *encrypt_data(void *arg) {
	sem_wait(&sem1); // Wait for read_data to complete
	for (int i = 0; i < strlen(file_data); i++) {
  	  file_data[i] ^= (hash_value & 0xFF); // Use lower 8 bits of hash as key
	}
	pthread_mutex_lock(&epipe_mutex);
	int pipe_fd = open(PIPE_PATH, O_WRONLY);
	if (pipe_fd == -1) {
  	  perror("Error opening named pipe for writing");
  	  exit(EXIT_FAILURE);
	}
	ssize_t x = write(pipe_fd, file_data, strlen(file_data));
	if (x == -1) {
  	  perror("Error writing to named pipe");
  	  exit(EXIT_FAILURE);
	}
	if (close(pipe_fd) == -1) {
	perror("Error closing named pipe");
	}
	pthread_mutex_unlock(&epipe_mutex);
    
	sem_post(&sem2); // Signal write_encrypted_data to proceed
	if (!file_name_exists("hash_values.txt", file_name)) {
  	  pthread_mutex_lock(&hash_mutex);
  	  FILE *hash_file = fopen("hash_values.txt", "a");
  	  if (hash_file == NULL) {
  		  perror("Error opening hash values file");
  		  exit(EXIT_FAILURE);
  	  }
  	  fprintf(hash_file, "%s,%u\n", file_name, hash_value);
  	  fclose(hash_file);
  	  pthread_mutex_unlock(&hash_mutex);
	}
	return NULL;
}


// Function to write encrypted data to file
void *write_encrypted_data(void *arg) {
	file_name = (char *)arg;
	char buffer[BUFFER_SIZE];
	sem_wait(&sem2); // Wait for encrypt_data to complete
	pthread_mutex_lock(&epipe_mutex);
	int pipe_fd = open("/tmp/encryption_pipe", O_RDWR);
	if (pipe_fd == -1) {
  	  perror("Error opening named pipe");
  	  exit(EXIT_FAILURE);
	}
	bytes_read = read(pipe_fd, buffer, BUFFER_SIZE);
	if ( bytes_read== -1) {
  	  perror("Error reading from named pipe");
  	  exit(EXIT_FAILURE);
	}
	if (close(pipe_fd) == -1) {
	perror("Error closing named pipe");
	}
	pthread_mutex_unlock(&epipe_mutex);
	FILE *file = fopen(file_name, "wb");
	if (file == NULL) {
  	  perror("Error opening file");
  	  exit(EXIT_FAILURE);
	}
	fwrite(buffer, 1, bytes_read, file);
	fclose(file);
	return NULL;
}



// Encryption function
void encryption(char *file_name) {
	// Create named pipe
	mkfifo(PIPE_PATH, 0666);


	// Initialize semaphore
	sem_init(&sem1, 0, 0);
	sem_init(&sem2, 0, 0);
	// Create threads
	pthread_t read_thread, encrypt_thread, write_thread;
	pthread_create(&read_thread, NULL, read_data, file_name);
	pthread_create(&encrypt_thread, NULL, encrypt_data, NULL);
	pthread_create(&write_thread, NULL, write_encrypted_data, file_name);

	// Run cat command to read from the pipe
	system("gnome-terminal -- /bin/sh -c 'cat /tmp/encryption_pipe'");

	// Join threads
	pthread_join(read_thread, NULL);
	pthread_join(encrypt_thread, NULL);
	pthread_join(write_thread, NULL);

	// Destroy mutex and semaphores
	pthread_mutex_destroy(&epipe_mutex);
	sem_destroy(&sem1);
	sem_destroy(&sem2);


	// Remove named pipe
	unlink(PIPE_PATH);
}











// Function to compare two strings alphabetically
int compare(const void *a, const void *b) {
	return strcmp(*(const char **)a, *(const char **)b);
}


// Global variables
char *files[MAX_FILES];
int file_count = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


// Function declarations
void *readFiles(void *arg);
void *sortFiles(void *arg);
void performSorting(const char *directory);


// Function to read files in directory and add them to the files array
void *readFiles(void *arg) {
	const char *directory = (const char *)arg;
	DIR *dir;
	struct dirent *entry;


	// Open directory
	dir = opendir(directory);
	if (dir == NULL) {
  	  perror("opendir");
  	  pthread_exit(NULL);
	}


	// Read all files in the directory
	while ((entry = readdir(dir)) != NULL) {
  	  if (entry->d_type == DT_REG) {
  		  pthread_mutex_lock(&mutex);
  		  if (file_count < MAX_FILES) {
  			  files[file_count++] = strdup(entry->d_name);
  		  }
  		  pthread_mutex_unlock(&mutex);
  	  }
	}


	// Close directory
	closedir(dir);
	pthread_exit(NULL);
}


// Function to sort files alphabetically
void *sortFiles(void *arg) {
	pthread_mutex_lock(&mutex);
	qsort(files, file_count, sizeof(char *), compare);
	pthread_mutex_unlock(&mutex);
	pthread_exit(NULL);
}


// Implement sorting functionality
void performSorting(const char *directory) {
	pthread_t read_thread, sort_thread;


	// Create thread to read files
	if (pthread_create(&read_thread, NULL, readFiles, (void *)directory) != 0) {
  	  perror("pthread_create");
  	  exit(EXIT_FAILURE);
	}


	// Wait for the read thread to finish
	if (pthread_join(read_thread, NULL) != 0) {
  	  perror("pthread_join");
  	  exit(EXIT_FAILURE);
	}


	// Create thread to sort files
	if (pthread_create(&sort_thread, NULL, sortFiles, NULL) != 0) {
  	  perror("pthread_create");
  	  exit(EXIT_FAILURE);
	}


	// Wait for the sort thread to finish
	if (pthread_join(sort_thread, NULL) != 0) {
  	  perror("pthread_join");
  	  exit(EXIT_FAILURE);
	}


	// Print sorted filenames
	printf("Sorted filenames:\n");
	for (int i = 0; i < file_count; i++) {
  	  printf("%s\n", files[i]);
	}


	// Free allocated memory for filenames
	for (int i = 0; i < file_count; i++) {
  	  free(files[i]);
	}
}




// Define mutex variable
pthread_mutex_t mutex;


typedef struct {
	char keyword[LEN];
	char filename[MAX];
} KeywordInfo;


typedef struct {
	KeywordInfo data[MAX_KEYWORDS];
	int count;
} HashTable;


typedef struct {
	char (*files)[MAX];
	int start;
	int end;
	HashTable *ht;
} ThreadArg;


unsigned int hash_function(char* str) {
	unsigned int hash = 5381;
	int c;
	while ((c = *str++)) {
  	  hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

//function to remove full stops and commas attached with keywords
void sanitize_keyword(char* keyword) {
	char* dst = keyword;
	for (char* src = keyword; *src; ++src) {
  	  if (*src != '.' && *src != ',') {
  		  *dst++ = *src;
  	  }
	}
	*dst = '\0';
}


void insert_keyword(HashTable* ht, char* keyword, char* filename) {
	sanitize_keyword(keyword);  // Remove punctuation


	// List of stop words to exclude
	char *stop_words[] = {"their", "would", "about", "which", "there", "after",
            			  "could", "other", "these", "also", "where", "years",
            			  "being", "before", "those","they"};//this is just a limit list


	// Check if the length of the keyword is greater than 3
	if (strlen(keyword) <= 3) {
  	  return; // Skip words with length less than or equal to 3
	}


	// Check if the keyword is in the list of stop words
	for (int i = 0; i < sizeof(stop_words) / sizeof(stop_words[0]); i++) {
  	  if (strcmp(keyword, stop_words[i]) == 0) {
  		  return; // Skip stop words
  	  }
	}


	unsigned int index = hash_function(keyword) % MAX_KEYWORDS;


	while (ht->data[index].keyword[0] != '\0') {
  	  index = (index + 1) % MAX_KEYWORDS;
	}


	strcpy(ht->data[index].keyword, keyword);
	strcpy(ht->data[index].filename, filename);
	ht->count++;
}


void *process_files(void *arg) {
	ThreadArg *targ = (ThreadArg *)arg;


	for (int i = targ->start; i < targ->end; i++) {
  	  if (strcmp(targ->files[i], "summary.txt") == 0) {
  		  continue;
  	  }//ignore summary.txt file while reading


  	  FILE* file = fopen(targ->files[i], "r");
  	  if (!file) {
  		  perror("fopen");
  		  continue;
  	  }


  	  char line[MAX];
  	  while (fgets(line, sizeof(line), file) != NULL) {
  		  char* token = strtok(line, " \t\n"); // Split by spaces,tabs, and newlines
  		  while (token != NULL) {
  			  if (strlen(token) > 3) {
      			  pthread_mutex_lock(&mutex);
      			  insert_keyword(targ->ht, token, targ->files[i]);
      			  pthread_mutex_unlock(&mutex);
  			  }
  			  token = strtok(NULL, " \t\n");
  		  }
  	  }


  	  fclose(file);
	}


	return NULL;
}


int search_keyword_linear_probe(HashTable *ht, char *key) {
	int found = 0;
	unsigned int index = hash_function(key) % MAX_KEYWORDS;
	int initial_index = index;


	do {
  	  if (strcmp(ht->data[index].keyword, key) == 0) {
  		  printf("Keyword: %s, Filename: %s\n",
ht->data[index].keyword, ht->data[index].filename);
  		  found = 1;
  	  }
  	  index = (index + 1) % MAX_KEYWORDS;
	} while (index != initial_index && ht->data[index].keyword[0] != '\0');


	return found; // Return if the word is found at least once
}


void initialize_shared_memory(HashTable *shared_memory) {
	// Initialize hash table
	for (int i = 0; i < MAX_KEYWORDS; i++) {
  	  shared_memory->data[i].keyword[0] = '\0';
	}
	shared_memory->count = 0;
}


void delete_summary_file() {
//in the above code ignoring summary.txt was not working sometimes so this method is to ensure that summary.txt is used while reading(deleting summay.txt at the start of code if it already exist)
	if (access("summary.txt", F_OK) != -1) {
  	  if (remove("summary.txt") != 0) {
  		  perror("Error deleting summary.txt");
  	  }
	}
}


void create_summary_file(HashTable *shared_memory) {
	FILE* summary_fp = fopen("summary.txt", "w");
	if (!summary_fp) {
  	  perror("fopen");
  	  exit(1);
	}
	for (int i = 0; i < MAX_KEYWORDS; i++) {
  	  if (shared_memory->data[i].keyword[0] != '\0') {
  		  fprintf(summary_fp, "%s,%s\n", shared_memory->data[i].keyword,
      			  shared_memory->data[i].filename);
  		  fflush(summary_fp); // Flush after each write
  	  }
	}
	fclose(summary_fp);
}


void process_files_and_search_keywords() {
	int shmid;
	HashTable *shared_memory;


	// Create shared memory segment
	shmid = shm_open("/my_shared_memory", O_CREAT | O_RDWR, 0666);
	if (shmid == -1) {
  	  perror("shm_open");
  	  exit(1);
	}


	// Truncate shared memory segment to the size of HashTable
	ftruncate(shmid, sizeof(HashTable));


	// Map shared memory segment
	shared_memory = mmap(NULL, sizeof(HashTable), PROT_READ |
PROT_WRITE, MAP_SHARED, shmid, 0);
	if (shared_memory == MAP_FAILED) {
  	  perror("mmap");
  	  exit(1);
	}


	// Initialize shared memory
	initialize_shared_memory(shared_memory);


	// Initialize the mutex
	pthread_mutex_init(&mutex, NULL);


	// Delete summary file if it exists
	delete_summary_file();


	// Fork a child process
	pid_t pid = fork();
	if (pid < 0) {
  	  perror("fork");
  	  exit(1);
	} else if (pid == 0) {
  	  DIR* dir = opendir(".");
  	  if (!dir) {
  		  perror("opendir");
  		  exit(1);
  	  }


  	  struct dirent* entry;
  	  char filepath[MAX_FILES][MAX];
  	  int file_count = 0;


  	  while ((entry = readdir(dir)) != NULL && file_count < MAX_FILES) {
  		  if (entry->d_type == DT_REG && strstr(entry->d_name, ".txt")) {
  			  snprintf(filepath[file_count],
sizeof(filepath[file_count]), "./%s", entry->d_name);
  			  file_count++;
  		  }
  	  }
  	  closedir(dir);


  	  pthread_t threads[THREAD_COUNT];
  	  ThreadArg args[THREAD_COUNT];
  	  int files_per_thread = file_count / THREAD_COUNT;


  	  for (int i = 0; i < THREAD_COUNT; i++) {
  		  args[i].files = filepath;
  		  args[i].start = i * files_per_thread;
  		  args[i].end = (i + 1) * files_per_thread;
  		  args[i].ht = shared_memory;
  		  if (i == THREAD_COUNT - 1) args[i].end = file_count;
  		  pthread_create(&threads[i], NULL, process_files, &args[i]);
  	  }


  	  for (int i = 0; i < THREAD_COUNT; i++) {
  		  pthread_join(threads[i], NULL);
  	  }


  	  pthread_mutex_destroy(&mutex);


  	  exit(0);
	} else {
  	  wait(NULL);


  	  // Create summary file
  	  create_summary_file(shared_memory);


  	  // Search keywords
  	  char search_key[LEN];
  	  do {
  		  printf("Enter the keyword to search (press '0' to exit): ");
  		  scanf("%s", search_key);
  		  if (strcmp(search_key, "0") == 0) {
  			  break; // Exit loop if user enters '0'
  		  }
  		  if (!search_keyword_linear_probe(shared_memory, search_key)) {
  			  printf("Keyword '%s' not found.\n", search_key);
  		  }
  	  } while (1);


  	  munmap(shared_memory, sizeof(HashTable));
  	  shm_unlink("/my_shared_memory");
	}
}




	int main(int argc, char *argv[]) {
	// Check if correct number of arguments is provided
	if (argc != 3) {
  	  fprintf(stderr, "Usage: %s <command> <directory>\n", argv[0]);
  	  return EXIT_FAILURE;
	}


	// Extract command and directory from command-line arguments
	const char *command = argv[1];
     char *directory = argv[2];




	// Check if the command is for sorting
	if (strcmp(command, "-s") == 0) {
  	  // Call sorting functionality
  	  performSorting(directory);
	}
	else if (strcmp(command,"-p")==0){
	process_files_and_search_keywords();
   }


   else if(strcmp(command,"-e")==0){


   fflush(stdout);
   encryption(directory);
  }
  else if(strcmp(command,"-d")==0){
  fflush(stdout);
   decryption(directory);


   }
   
   else if(strcmp(command,"-c")==0){


   fflush(stdout);
   createfile(directory);
   
  }
 
 
  else if(strcmp(command,"-r")==0){


   fflush(stdout);
   
	renamefile(directory);
  }
 
 
  else if(strcmp(command,"-del")==0){


   fflush(stdout);
   deletefile(directory);
  }




	else {
  	  fprintf(stderr, "Unknown command: %s\n", command);
  	  return EXIT_FAILURE;
	}


	return EXIT_SUCCESS;
}

