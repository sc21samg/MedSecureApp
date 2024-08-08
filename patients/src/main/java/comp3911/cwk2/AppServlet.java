package comp3911.cwk2;

import java.io.File;
import java.io.IOException;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

import org.mindrot.jbcrypt.BCrypt;

@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

  private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
  private static final String AUTH_QUERY = "select * from user where username='%s' and password='%s'";
  private static final String SEARCH_QUERY = "select * from patient where surname='%s' collate nocase";

  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;

  @Override
public void init() throws ServletException {
  configureTemplateEngine();
  connectToDatabase();

  try {
    encryptExistingPasswords(); // Call the method to encrypt existing passwords
  } catch (SQLException e) {
    throw new ServletException("Error encrypting existing passwords: " + e.getMessage());
  }
}



  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);
    }
    catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
    }
    catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
          throws ServletException, IOException {
    try {
      Template template = fm.getTemplate("login.html");
      template.process(null, response.getWriter());
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (TemplateException error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
          throws ServletException, IOException {
    // Get form parameters
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String surname = request.getParameter("surname");
    Map<String, Object> model = new HashMap<>();

    try {
      if (authenticated(username, password, surname, model)) {
        // Get search results and merge with template
        model.put("records", searchResults(surname));
        Template template = fm.getTemplate("details.html");
        template.process(model, response.getWriter());
      }
      else {
        Template template = fm.getTemplate("invalid.html");
        template.process(model, response.getWriter());
      }
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (Exception error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  // Method to hash the password before storing it
private String hashPassword(String password) {
  return BCrypt.hashpw(password, BCrypt.gensalt());
}

// Method to check if the provided password matches the stored hashed password
private boolean checkPassword(String plainPassword, String hashedPassword) {
  return BCrypt.checkpw(plainPassword, hashedPassword);
}

// Use hashPassword method when registering a new user or setting a password
// Example:
String plainPassword = "user_password";
String hashedPassword = hashPassword(plainPassword);
// Store hashedPassword in the database along with other user details

// Modify your authentication logic to compare hashed passwords
private boolean authenticated(String username, String password, String surname, Map<String, Object> model) throws SQLException {
  String query = "select * from user where username=?";
  try (PreparedStatement stmt = database.prepareStatement(query)) {
      stmt.setString(1, username);
      ResultSet results = stmt.executeQuery();
      if (results.next()) {
          String hashedPassword = results.getString("password"); // Retrieve hashed password from the database
          if (checkPassword(password, hashedPassword)) {
              int userId = results.getInt("id");
              if (hasAccess(userId, surname)) {
                  return true; // Authentication successful and has access
              } else {
                  model.put("error", "Access Denied: The requested patient data is either unavailable or does not exist in the database. Please ensure you have the necessary permissions and verify the patient's information.");
              }
          } else {
              model.put("error", "Invalid username or password.");
          }
      } else {
          model.put("error", "Invalid username or password.");
      }
      return false; // Authentication failed
  }
}

  // Modify the hasAccess method to check if the authenticated user has access to the patient records
  private boolean hasAccess(int userId, String patientSurname) throws SQLException {
    String accessCheckQuery = "SELECT COUNT(*) FROM patient WHERE gp_id=? AND surname=?";
    try (PreparedStatement stmt = database.prepareStatement(accessCheckQuery)) {
      stmt.setInt(1, userId);
      stmt.setString(2, patientSurname);
      ResultSet results = stmt.executeQuery();
      return results.getInt(1) > 0;
    }
  }

  public void encryptExistingPasswords() throws SQLException {
    String retrieveQuery = "SELECT id, password FROM user";
    try (PreparedStatement stmt = database.prepareStatement(retrieveQuery)) {
        ResultSet results = stmt.executeQuery();
        while (results.next()) {
            int userId = results.getInt("id");
            String currentHashedPassword = results.getString("password");

            // Check if the password needs encryption
            if (!currentHashedPassword.startsWith("$2a$")) { // Check if it's already hashed (BCrypt)
                String newHashedPassword = hashPassword(currentHashedPassword);

                // Update the password in the database
                String updateQuery = "UPDATE user SET password=? WHERE id=?";
                try (PreparedStatement updateStmt = database.prepareStatement(updateQuery)) {
                    updateStmt.setString(1, newHashedPassword);
                    updateStmt.setInt(2, userId);
                    updateStmt.executeUpdate();
                }
            }
        }
    }
}


  private List<Record> searchResults(String surname) throws SQLException {
    List<Record> records = new ArrayList<>();
    //Prevent SQL Injection by replacing statement with PreparedStatement
    String query = "select * from patient where surname=? collate nocase";
    try (PreparedStatement stmt = database.prepareStatement(query)) {
      stmt.setString(1, surname);
      ResultSet results = stmt.executeQuery();
      while (results.next()) {
        Record rec = new Record();
        rec.setSurname(results.getString(2));
        rec.setForename(results.getString(3));
        rec.setAddress(results.getString(4));
        rec.setDateOfBirth(results.getString(5));
        rec.setDoctorId(results.getString(6));
        rec.setDiagnosis(results.getString(7));
        records.add(rec);
      }
    }
    return records;
  }
}
