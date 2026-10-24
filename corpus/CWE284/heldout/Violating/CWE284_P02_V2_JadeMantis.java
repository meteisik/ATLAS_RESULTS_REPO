import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_JadeMantis {
    private static boolean privateTrue = true;

    public void deleteJadeMantisAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (privateTrue) {
                data = System.getenv("JADE_MANTIS_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection jadeMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeMantis");
            try {
                PreparedStatement jadeMantisDelete = jadeMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                jadeMantisDelete.setString(1, data);
                jadeMantisDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                jadeMantisConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
