import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_MosaicLotus {

    public void deleteMosaicLotusAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_LOTUS_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_MosaicLotusSink()).applyMosaicLotusDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_MosaicLotusSink {
    public void applyMosaicLotusDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLotus");
        try {
            PreparedStatement mosaicLotusDelete = mosaicLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicLotusDelete.setString(1, data);
            mosaicLotusDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            mosaicLotusConnection.close();
        }
    }
}
