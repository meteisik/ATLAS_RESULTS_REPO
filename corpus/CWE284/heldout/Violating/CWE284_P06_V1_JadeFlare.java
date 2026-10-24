import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_JadeFlare {

    public void deleteJadeFlareAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_FLARE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_JadeFlareSink()).applyJadeFlareDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_JadeFlareSink {
    public void applyJadeFlareDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeFlare");
        try {
            PreparedStatement jadeFlareDelete = jadeFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeFlareDelete.setString(1, data);
            jadeFlareDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            jadeFlareConnection.close();
        }
    }
}
