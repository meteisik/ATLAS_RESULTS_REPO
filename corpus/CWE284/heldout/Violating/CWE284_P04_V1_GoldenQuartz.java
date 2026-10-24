import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_GoldenQuartz {

    private boolean checkGoldenQuartzAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteGoldenQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_QUARTZ_ACCOUNT_ID");
        boolean authorized = checkGoldenQuartzAccess(data);
        Connection goldenQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenQuartz");
        try {
            PreparedStatement goldenQuartzDelete = goldenQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenQuartzDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenQuartzDelete.executeUpdate();
            }
        } finally {
            goldenQuartzConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
