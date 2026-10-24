import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AmberMantisSafe {

    public void deleteAmberMantisAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_MANTIS_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection amberMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberMantis");
        try {
            PreparedStatement amberMantisDelete = amberMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberMantisDelete.setString(1, data);
            if (authorized) {
                amberMantisDelete.executeUpdate();
            }
        } finally {
            amberMantisConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
