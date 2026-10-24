import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_GoldenQuartzSafe {

    public void deleteGoldenQuartzAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("GOLDEN_QUARTZ_ACCOUNT_ID");
            break;
        }
        boolean authorized = isAuthorized(data);
        Connection goldenQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenQuartz");
        try {
            PreparedStatement goldenQuartzDelete = goldenQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenQuartzDelete.setString(1, data);
            if (authorized) {
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
