import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_GoldenMantisSafe {

    public void deleteGoldenMantisAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("GOLDEN_MANTIS_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection goldenMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenMantis");
            try {
                PreparedStatement goldenMantisDelete = goldenMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                goldenMantisDelete.setString(1, data);
                if (authorized) {
                    goldenMantisDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                goldenMantisConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
