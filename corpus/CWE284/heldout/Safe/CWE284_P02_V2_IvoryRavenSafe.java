import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_IvoryRavenSafe {

    public void deleteIvoryRavenAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            switch (7) {
            case 7:
                data = System.getenv("IVORY_RAVEN_ACCOUNT_ID");
                break;
            default:
                data = null;
                break;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection ivoryRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryRaven");
            try {
                PreparedStatement ivoryRavenDelete = ivoryRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                ivoryRavenDelete.setString(1, data);
                if (authorized) {
                    ivoryRavenDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                ivoryRavenConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
