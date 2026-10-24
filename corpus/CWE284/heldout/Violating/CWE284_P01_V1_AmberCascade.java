import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AmberCascade {

    public void deleteAmberCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_CASCADE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection amberCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCascade");
        try {
            PreparedStatement amberCascadeDelete = amberCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberCascadeDelete.setString(1, data);
            amberCascadeDelete.executeUpdate();
        } finally {
            amberCascadeConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
