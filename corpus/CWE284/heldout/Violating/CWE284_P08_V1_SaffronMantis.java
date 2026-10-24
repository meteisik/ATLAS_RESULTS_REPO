import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_SaffronMantis {

    public void deleteSaffronMantisAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_MANTIS_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_SaffronMantisSink()).applySaffronMantisDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_SaffronMantisSink {
    public void applySaffronMantisDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection saffronMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronMantis");
        try {
            PreparedStatement saffronMantisDelete = saffronMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronMantisDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                saffronMantisDelete.executeUpdate();
            }
        } finally {
            saffronMantisConnection.close();
        }
    }
}
