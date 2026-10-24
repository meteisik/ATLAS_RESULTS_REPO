import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_GoldenGlint {

    public void deleteGoldenGlintAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("GOLDEN_GLINT_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection goldenGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenGlint");
            try {
                PreparedStatement goldenGlintDelete = goldenGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                goldenGlintDelete.setString(1, data);
                goldenGlintDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                goldenGlintConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
