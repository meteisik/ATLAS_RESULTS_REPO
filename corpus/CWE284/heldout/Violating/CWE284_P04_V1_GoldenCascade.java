import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_GoldenCascade {

    private boolean checkGoldenCascadeAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteGoldenCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_CASCADE_ACCOUNT_ID");
        boolean authorized = checkGoldenCascadeAccess(data);
        Connection goldenCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCascade");
        try {
            PreparedStatement goldenCascadeDelete = goldenCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenCascadeDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenCascadeDelete.executeUpdate();
            }
        } finally {
            goldenCascadeConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
