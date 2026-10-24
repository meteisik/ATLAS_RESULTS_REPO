import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_JadeMantis {

    public void deleteJadeMantisAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_MANTIS_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_JadeMantisSink()).applyJadeMantisDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_JadeMantisSink {
    public void applyJadeMantisDeletion(String data, boolean authorized) throws SQLException {
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
