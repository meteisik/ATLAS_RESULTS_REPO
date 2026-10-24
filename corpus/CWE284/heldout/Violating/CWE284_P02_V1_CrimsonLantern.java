import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_CrimsonLantern {

    public void deleteCrimsonLanternAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("CRIMSON_LANTERN_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection crimsonLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLantern");
            try {
                PreparedStatement crimsonLanternDelete = crimsonLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                crimsonLanternDelete.setString(1, data);
                crimsonLanternDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                crimsonLanternConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
