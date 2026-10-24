import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_JadeFlareSafe {

    private String jadeFlareAccountId;

    private boolean jadeFlareAuthorized;

    private void applyJadeFlareDeletion() throws SQLException {
        String data = jadeFlareAccountId;
        boolean authorized = jadeFlareAuthorized;
        Connection jadeFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeFlare");
        try {
            PreparedStatement jadeFlareDelete = jadeFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeFlareDelete.setString(1, data);
            if (authorized) {
                jadeFlareDelete.executeUpdate();
            }
        } finally {
            jadeFlareConnection.close();
        }
    }

    public void deleteJadeFlareAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_FLARE_ACCOUNT_ID");
        jadeFlareAccountId = data;
        jadeFlareAuthorized = isAuthorized(data);
        applyJadeFlareDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
