import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AmberSundial {

    public void deleteAmberSundialAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_SUNDIAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection amberSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberSundial");
        try {
            PreparedStatement amberSundialDelete = amberSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberSundialDelete.setString(1, data);
            amberSundialDelete.executeUpdate();
        } finally {
            amberSundialConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
