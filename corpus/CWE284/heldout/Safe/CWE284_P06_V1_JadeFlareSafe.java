import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_JadeFlareSafe {

    public void deleteJadeFlareAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_FLARE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_JadeFlareSafeSink()).applyJadeFlareDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_JadeFlareSafeSink {
    public void applyJadeFlareDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeFlare");
        try {
            PreparedStatement jadeFlareDelete = jadeFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeFlareDelete.setString(1, data);
            if (authorized) {
                jadeFlareDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            jadeFlareConnection.close();
        }
    }
}
