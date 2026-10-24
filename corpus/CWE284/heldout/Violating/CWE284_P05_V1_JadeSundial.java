import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_JadeSundial {

    private String jadeSundialAccountId;

    private boolean jadeSundialAuthorized;

    private void applyJadeSundialDeletion() throws SQLException {
        String data = jadeSundialAccountId;
        boolean authorized = jadeSundialAuthorized;
        Connection jadeSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeSundial");
        try {
            PreparedStatement jadeSundialDelete = jadeSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeSundialDelete.setString(1, data);
            jadeSundialDelete.executeUpdate();
        } finally {
            jadeSundialConnection.close();
        }
    }

    public void deleteJadeSundialAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_SUNDIAL_ACCOUNT_ID");
        jadeSundialAccountId = data;
        jadeSundialAuthorized = isAuthorized(data);
        applyJadeSundialDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
