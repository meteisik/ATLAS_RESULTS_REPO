import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_GoldenSundial {

    public void deleteGoldenSundialAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("GOLDEN_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection goldenSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenSundial");
        try {
            PreparedStatement goldenSundialDelete = goldenSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenSundialDelete.setString(1, data);
            goldenSundialDelete.executeUpdate();
        } finally {
            goldenSundialConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
