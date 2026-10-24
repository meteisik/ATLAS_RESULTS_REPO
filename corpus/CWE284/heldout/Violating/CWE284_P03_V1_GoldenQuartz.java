import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_GoldenQuartz {

    private void applyGoldenQuartzDeletion(String data, boolean authorized) throws SQLException {
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

    public void deleteGoldenQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_QUARTZ_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyGoldenQuartzDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
