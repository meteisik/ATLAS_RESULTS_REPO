import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_GoldenCascadeSafe {

    private void applyGoldenCascadeDeletion(String data, boolean authorized) throws SQLException {
        Connection goldenCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCascade");
        try {
            PreparedStatement goldenCascadeDelete = goldenCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenCascadeDelete.setString(1, data);
            if (authorized) {
                goldenCascadeDelete.executeUpdate();
            }
        } finally {
            goldenCascadeConnection.close();
        }
    }

    public void deleteGoldenCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_CASCADE_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyGoldenCascadeDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
