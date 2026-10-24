import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_CrimsonKestrel {

    public void deleteCrimsonKestrelAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("CRIMSON_KESTREL_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection crimsonKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonKestrel");
            try {
                PreparedStatement crimsonKestrelDelete = crimsonKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                crimsonKestrelDelete.setString(1, data);
                crimsonKestrelDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                crimsonKestrelConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
