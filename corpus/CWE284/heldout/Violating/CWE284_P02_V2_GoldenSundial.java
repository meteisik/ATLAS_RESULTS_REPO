import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_GoldenSundial {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteGoldenSundialAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_TRUE) {
                data = System.getenv("GOLDEN_SUNDIAL_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection goldenSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenSundial");
            try {
                PreparedStatement goldenSundialDelete = goldenSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                goldenSundialDelete.setString(1, data);
                goldenSundialDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                goldenSundialConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
