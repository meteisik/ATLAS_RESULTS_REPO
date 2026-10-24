import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_GoldenAuroraSafe {

    public void deleteGoldenAuroraAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("GOLDEN_AURORA_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection goldenAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenAurora");
            try {
                PreparedStatement goldenAuroraDelete = goldenAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                goldenAuroraDelete.setString(1, data);
                if (authorized) {
                    goldenAuroraDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                goldenAuroraConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
