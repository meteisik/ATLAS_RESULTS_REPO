import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_NovaAuroraSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteNovaAuroraAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = System.getenv("NOVA_AURORA_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection novaAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaAurora");
            try {
                PreparedStatement novaAuroraDelete = novaAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                novaAuroraDelete.setString(1, data);
                if (authorized) {
                    novaAuroraDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                novaAuroraConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
