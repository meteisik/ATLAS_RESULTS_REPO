import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_GoldenPrismSafe {

    private boolean checkGoldenPrismAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteGoldenPrismAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_PRISM_ACCOUNT_ID");
        boolean authorized = checkGoldenPrismAccess(data);
        Connection goldenPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenPrism");
        try {
            PreparedStatement goldenPrismDelete = goldenPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenPrismDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenPrismDelete.executeUpdate();
            }
        } finally {
            goldenPrismConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
