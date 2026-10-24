import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_JadeAurora {

    public void deleteJadeAuroraAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            while (true) {
                data = System.getenv("JADE_AURORA_ACCOUNT_ID");
                break;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection jadeAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeAurora");
            try {
                PreparedStatement jadeAuroraDelete = jadeAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                jadeAuroraDelete.setString(1, data);
                jadeAuroraDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                jadeAuroraConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
