import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_CobaltRavenSafe {

    public void deleteCobaltRavenAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("COBALT_RAVEN_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection cobaltRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltRaven");
            try {
                PreparedStatement cobaltRavenDelete = cobaltRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                cobaltRavenDelete.setString(1, data);
                if (authorized) {
                    cobaltRavenDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                cobaltRavenConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
