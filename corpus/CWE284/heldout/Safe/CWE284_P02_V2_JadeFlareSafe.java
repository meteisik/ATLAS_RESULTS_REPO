import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_JadeFlareSafe {

    public void deleteJadeFlareAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (5 == 5) {
                data = System.getenv("JADE_FLARE_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
